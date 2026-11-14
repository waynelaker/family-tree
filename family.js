/*
FAMILY DATA MODEL
- Edit family.json locally, then run `node encrypt-family.mjs` to refresh family.enc.json.
- Publish only the encrypted file; keep plaintext data and backups out of the public repository.
- Each descendant has a unique number string and name; number "0" is the root.
- Descendants are top-level records; each person's partners are nested in `partnerships`.
- Each partnership has a partner `name` and a `children` array of descendant number strings.
- Optional `parents` arrays on the root and its partners describe ancestors shown above them.
- Set `color` (hex) and `colourName` on each child of root "0"; descendants inherit that line color.
- Dates are YEAR ONLY: `birthYear` and optional `deathYear`.
- Use an empty `children` array when a partnership has no children.
*/
function decodeBase64(value, field) {
  if (
    typeof value !== "string" ||
    value.length % 4 !== 0 ||
    !/^[A-Za-z0-9+/]*={0,2}$/.test(value)
  ) {
    throw new Error(`Encrypted family data has an invalid ${field}.`);
  }
  return Uint8Array.from(atob(value), character => character.charCodeAt(0));
}

class FamilyDecryptionError extends Error {
  constructor() {
    super("Incorrect password.");
    this.name = "FamilyDecryptionError";
  }
}

async function fetchEncryptedFamily() {
  if (!globalThis.crypto?.subtle) {
    throw new Error("Browser encryption is unavailable; open the site over HTTPS.");
  }
  const response = await fetch("family.enc.json");
  if (!response.ok) {
    throw new Error(`Could not load encrypted family data (HTTP ${response.status}).`);
  }
  const envelope = await response.json();
  if (
    envelope?.version !== 1 ||
    envelope.kdf !== "PBKDF2-SHA-256" ||
    envelope.cipher !== "AES-GCM" ||
    !Number.isInteger(envelope.iterations) ||
    envelope.iterations < 100_000 ||
    envelope.iterations > 1_000_000
  ) {
    throw new Error("Encrypted family data has an unsupported format.");
  }

  const salt = decodeBase64(envelope.salt, "salt");
  const iv = decodeBase64(envelope.iv, "nonce");
  const ciphertext = decodeBase64(envelope.ciphertext, "ciphertext");
  if (salt.length !== 16 || iv.length !== 12 || ciphertext.length < 16) {
    throw new Error("Encrypted family data is incomplete or damaged.");
  }
  return { iterations: envelope.iterations, salt, iv, ciphertext };
}

async function deriveFamilyKey(password, envelope) {
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  const key = await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: envelope.salt,
      iterations: envelope.iterations,
      hash: "SHA-256"
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"]
  );
  return key;
}

async function decryptFamily(envelope, key) {
  let plaintext;
  try {
    plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: envelope.iv },
      key,
      envelope.ciphertext
    );
  } catch (error) {
    if (error.name === "OperationError") throw new FamilyDecryptionError();
    throw error;
  }

  try {
    return JSON.parse(new TextDecoder().decode(plaintext));
  } catch (error) {
    throw new Error("The decrypted family data is not valid JSON.", { cause: error });
  }
}

async function loadFamily(password) {
  const envelope = await fetchEncryptedFamily();
  const key = await deriveFamilyKey(password, envelope);
  return { family: await decryptFamily(envelope, key), key };
}

function openRememberedKeyDatabase() {
  if (!globalThis.indexedDB) {
    throw new Error("This browser does not support remembering access.");
  }
  return new Promise((resolve, reject) => {
    const request = indexedDB.open("family-tree-access", 1);
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains("keys")) {
        request.result.createObjectStore("keys");
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error || new Error("Could not open browser storage."));
    request.onblocked = () => reject(new Error("Browser storage is blocked by another page."));
  });
}

async function useRememberedKeyStore(mode, operation) {
  const database = await openRememberedKeyDatabase();
  return new Promise((resolve, reject) => {
    let result;
    let transaction;
    const fail = error => {
      database.close();
      reject(error);
    };

    try {
      transaction = database.transaction("keys", mode);
      transaction.oncomplete = () => {
        database.close();
        resolve(result);
      };
      transaction.onerror = () => fail(
        transaction.error || new Error("Could not update browser storage.")
      );
      transaction.onabort = () => fail(
        transaction.error || new Error("Browser storage operation was cancelled.")
      );
      const request = operation(transaction.objectStore("keys"));
      if (request) {
        request.onsuccess = () => {
          result = request.result;
        };
        request.onerror = () => fail(
          request.error || new Error("Could not access browser storage.")
        );
      }
    } catch (error) {
      fail(error);
    }
  });
}

function getRememberedKey() {
  return useRememberedKeyStore("readonly", store => store.get("family-key"));
}

function saveRememberedKey(key) {
  return useRememberedKeyStore("readwrite", store => store.put(key, "family-key"));
}

function deleteRememberedKey() {
  return useRememberedKeyStore("readwrite", store => store.delete("family-key"));
}

function setUnlockStatus(message, isError = false) {
  unlockStatus.classList.toggle("error", isError);
  unlockStatus.textContent = message;
}

function showFamily(family) {
  unlockPanel.hidden = true;
  familyApp.hidden = false;
  document.querySelector("#browserStatus").textContent = "";
  document.querySelector("#browserStatus").hidden = true;
  try {
    initializeFamily(family);
    return true;
  } catch (error) {
    console.error("Could not initialize the family tree.", error);
    familyApp.hidden = true;
    unlockPanel.hidden = false;
    setUnlockStatus("The family data decrypted but the tree could not be displayed.", true);
    return false;
  }
}

async function restoreRememberedFamily() {
  try {
    const key = await getRememberedKey();
    if (!key) return;
    if (
      key.type !== "secret" ||
      key.algorithm?.name !== "AES-GCM" ||
      !key.usages?.includes("decrypt")
    ) {
      await deleteRememberedKey();
      setUnlockStatus("The saved browser key is invalid. Enter the password again.", true);
      return;
    }

    const envelope = await fetchEncryptedFamily();
    let family;
    try {
      family = await decryptFamily(envelope, key);
    } catch (error) {
      if (!(error instanceof FamilyDecryptionError)) throw error;
      await deleteRememberedKey();
      setUnlockStatus(
        "The saved key no longer matches the encrypted family data. Enter the current password.",
        true
      );
      return;
    }
    showFamily(family);
  } catch (error) {
    console.error("Could not restore remembered family access.", error);
    setUnlockStatus(
      "Could not check remembered access. Enter the password to continue.",
      true
    );
  }
}

function initializeFamily(FAMILY) {
  "use strict";

  const $ = selector => document.querySelector(selector);
  const svg = $("#familyTree");
  const viewport = $("#treeViewport");
  const canvas = $("#treeCanvas");
  const directory = $("#directory");
  const search = $("#search");
  const rootId = "0";
  const W = 184;
  const H = 86;
  const FOCUS_W = 232;
  const FOCUS_H = 108;
  const HORIZONTAL_GAP = 208;
  const FOCUS_GAP = 260;
  const SUBTREE_GAP = 24;
  const UNION_TRACK_GAP = 10;
  const CROSSING_JUMP_HALF_WIDTH = 3;
  const CROSSING_JUMP_HEIGHT = 4;
  const ROW_GAP = 220;
  const ROOT_Y = 24;
  const people = new Map();
  for (const person of FAMILY.people) {
    const id = String(person.number);
    if (!/^(0|[1-9]\d*)$/.test(id)) {
      throw new Error(`Invalid descendant number "${id}". Use a unique number string.`);
    }
    if (people.has(id)) throw new Error(`Duplicate descendant number "${id}".`);
    people.set(id, { ...person, id, number: Number(id) });
  }

  const relationshipRecords = [];
  for (const person of FAMILY.people) {
    const ownerId = String(person.number);
    (person.partnerships || []).forEach((partnership, index) => {
      const partnerId = `partner:${ownerId}:${index + 1}`;
      people.set(partnerId, {
        id: partnerId,
        name: partnership.name,
        birthYear: partnership.birthYear,
        deathYear: partnership.deathYear,
        parents: partnership.parents
      });
      relationshipRecords.push({
        id: `${ownerId}:partnership:${index + 1}`,
        ownerId,
        partners: [ownerId, partnerId],
        children: (partnership.children || []).map(String),
        label: partnership.label
      });
    });
  }
  const focusPersonIds = new Set([rootId]);
  for (const union of relationshipRecords) {
    if (union.ownerId !== rootId) continue;
    union.partners.forEach(id => focusPersonIds.add(id));
  }
  const cardSize = id => focusPersonIds.has(id)
    ? { width: FOCUS_W, height: FOCUS_H }
    : { width: W, height: H };
  const personOrder = new Map([...people.keys()].map((id, index) => [id, index]));
  const unions = new Map(relationshipRecords.map(union => [union.id, union]));
  const unionsByPerson = new Map([...people.keys()].map(id => [id, []]));
  const parentsByChild = new Map();

  for (const union of unions.values()) {
    union.partners.forEach(id => {
      if (!unionsByPerson.has(id)) unionsByPerson.set(id, []);
      unionsByPerson.get(id).push(union.id);
    });
    for (const childId of union.children) {
      if (!parentsByChild.has(childId)) parentsByChild.set(childId, new Set());
      parentsByChild.get(childId).add(union.ownerId);
    }
  }

  const ancestorGroups = [];
  function addAncestorGroup(childId, parentRecords, groupId) {
    if (!Array.isArray(parentRecords) || parentRecords.length === 0) return;
    const parentIds = parentRecords.map((parent, index) => {
      if (!parent?.name) throw new Error(`Ancestor ${index + 1} for "${childId}" needs a name.`);
      const id = `ancestor:${groupId}:${index + 1}`;
      people.set(id, {
        id,
        name: parent.name,
        birthYear: parent.birthYear,
        deathYear: parent.deathYear,
        isAncestor: true
      });
      return id;
    });
    ancestorGroups.push({ id: `ancestors:${groupId}`, childId, parentIds });
  }
  const rootPerson = people.get(rootId);
  addAncestorGroup(rootId, rootPerson?.parents, rootId);
  for (const union of unions.values()) {
    if (union.ownerId !== rootId) continue;
    const partnerId = union.partners.find(id => id !== rootId);
    addAncestorGroup(partnerId, people.get(partnerId)?.parents, partnerId);
  }

  const namedColors = new Map([
    ["red", "#c62828"],
    ["kelly green", "#009c4f"],
    ["bright royal blue", "#4169e1"],
    ["purple", "#743f9f"],
    ["black", "#333333"],
    ["gold", "#b8860b"],
    ["navy", "#1b3a73"]
  ]);
  const colorForPerson = person => {
    const color = person?.color;
    if (typeof color === "string" && /^#[\da-f]{6}$/i.test(color)) return color.toLowerCase();
    const colorName = String(person?.colourName || person?.colorName || "").trim().toLowerCase();
    return namedColors.get(colorName) || null;
  };
  const familyLineColors = new Map();
  const colorQueue = [];
  for (const union of unions.values()) {
    if (union.ownerId !== rootId) continue;
    for (const childId of union.children) {
      const color = colorForPerson(people.get(childId));
      if (color) colorQueue.push({ id: childId, color });
    }
  }
  while (colorQueue.length) {
    const { id, color } = colorQueue.shift();
    if (familyLineColors.has(id)) continue;
    familyLineColors.set(id, color);
    for (const unionId of unionsByPerson.get(id) || []) {
      const union = unions.get(unionId);
      if (union.ownerId !== id) continue;
      for (const childId of union.children) colorQueue.push({ id: childId, color });
    }
  }

  const descendants = [...people.values()]
    .filter(person => Number.isInteger(person.number) && person.number > 0)
    .sort((a, b) => a.number - b.number);
  const partnerEntries = [...unions.values()].map(union => {
    const id = union.partners.find(partnerId => partnerId !== union.ownerId);
    return {
      id,
      ownerId: union.ownerId,
      person: people.get(id),
      owner: people.get(union.ownerId)
    };
  });
  const expandableIds = new Set(
    [...unions.values()]
      .filter(union => union.children.length)
      .map(union => union.ownerId)
  );
  const expanded = new Set([rootId]);
  let scale = 1;
  let tx = 24;
  let ty = 24;
  let dragging = false;
  let dragged = false;
  let dragStart = null;
  let pointerStart = null;
  let pointerTargetId = null;
  let pointerClickId = null;
  let layout = null;

  const years = person => {
    if (person.birthYear == null) return "";
    return person.deathYear
      ? `${person.birthYear}–${person.deathYear}`
      : `b. ${person.birthYear}`;
  };

  function colorTint(color) {
    const channels = [1, 3, 5].map(index => {
      const value = Number.parseInt(color.slice(index, index + 2), 16);
      return Math.round(value * 0.14 + 255 * 0.86).toString(16).padStart(2, "0");
    });
    return `#${channels.join("")}`;
  }

  function connectedPeople() {
    const connected = new Set([rootId]);
    const pending = [rootId];

    while (pending.length) {
      const id = pending.pop();
      for (const unionId of unionsByPerson.get(id) || []) {
        const union = unions.get(unionId);
        if (union.ownerId !== id) continue;
        if (!expanded.has(id)) continue;
        union.partners.forEach(partnerId => connected.add(partnerId));
        for (const childId of union.children || []) {
          if (connected.has(childId)) continue;
          connected.add(childId);
          pending.push(childId);
        }
      }
    }

    return connected;
  }

  function generationMap(connected) {
    const generations = new Map([[rootId, 0]]);
    let changed = true;
    let passes = 0;

    while (changed && passes <= people.size) {
      changed = false;
      passes++;

      for (const union of unions.values()) {
        const parentGeneration = generations.get(union.ownerId);
        if (!Number.isInteger(parentGeneration)) continue;

        for (const id of union.partners) {
          if (connected.has(id) && !generations.has(id)) {
            generations.set(id, parentGeneration);
            changed = true;
          }
        }

        if (!expanded.has(union.ownerId)) continue;
        for (const id of union.children || []) {
          if (!connected.has(id)) continue;
          const nextGeneration = parentGeneration + 1;
          if (!generations.has(id) || generations.get(id) < nextGeneration) {
            generations.set(id, nextGeneration);
            changed = true;
          }
        }
      }
    }

    if (changed) throw new Error("Family relationships contain a cycle.");
    return generations;
  }

  function orderKey(id) {
    const person = people.get(id);
    if (Number.isInteger(person.number)) return person.number;

    const partnerNumbers = new Set();
    const childNumbers = new Set();
    for (const unionId of unionsByPerson.get(id) || []) {
      const union = unions.get(unionId);
      for (const partnerId of union.partners) {
        if (partnerId === id) continue;
        const number = people.get(partnerId)?.number;
        if (Number.isInteger(number)) partnerNumbers.add(number);
      }
      for (const childId of union.children || []) {
        const number = people.get(childId)?.number;
        if (Number.isInteger(number)) childNumbers.add(number);
      }
    }

    const relatedNumbers = partnerNumbers.size ? partnerNumbers : childNumbers;
    return relatedNumbers.size
      ? [...relatedNumbers].reduce((sum, number) => sum + number, 0) / relatedNumbers.size
      : 0;
  }

  function orderedLayer(ids, generations) {
    const remaining = new Set(ids);
    const components = [];

    while (remaining.size) {
      const first = remaining.values().next().value;
      const component = [];
      const pending = [first];
      remaining.delete(first);

      while (pending.length) {
        const id = pending.pop();
        component.push(id);
        for (const unionId of unionsByPerson.get(id) || []) {
          const union = unions.get(unionId);
          for (const partnerId of union.partners) {
            if (generations.get(partnerId) === generations.get(id) && remaining.delete(partnerId)) {
              pending.push(partnerId);
            }
          }
        }
      }

      component.sort((a, b) =>
        orderKey(a) - orderKey(b) || personOrder.get(a) - personOrder.get(b)
      );
      components.push(component);
    }

    components.sort((a, b) => {
      const key = component => {
        const numbers = component
          .map(id => people.get(id).number)
          .filter(Number.isInteger);
        const values = numbers.length ? numbers : component.map(orderKey);
        return values.reduce((sum, value) => sum + value, 0) / values.length;
      };
      return key(a) - key(b) ||
        Math.min(...a.map(id => personOrder.get(id))) - Math.min(...b.map(id => personOrder.get(id)));
    });

    return components;
  }

  function memberSlots(partnerCount, spacing = HORIZONTAL_GAP) {
    const slots = Array.from(
      { length: partnerCount + 1 },
      (_, index) => (index - partnerCount / 2) * spacing
    );
    const ownerIndex = Math.floor(partnerCount / 2);
    return {
      owner: slots[ownerIndex],
      partners: slots.filter((_, index) => index !== ownerIndex)
    };
  }

  function calculate() {
    if (!people.has(rootId)) throw new Error('Family tree needs a descendant with number "0".');
    const rootUnions = (unionsByPerson.get(rootId) || [])
      .map(unionId => unions.get(unionId))
      .filter(union => union.ownerId === rootId);
    if (!rootUnions.length || !rootUnions.some(union => union.children.length)) {
      throw new Error('Descendant "0" needs a partnership with children.');
    }

    const connected = connectedPeople();
    const generations = generationMap(connected);
    const layerIds = new Map();
    for (const id of connected) {
      if (!people.has(id) || !generations.has(id)) continue;
      const generation = generations.get(id);
      if (!layerIds.has(generation)) layerIds.set(generation, []);
      layerIds.get(generation).push(id);
    }

    const componentsByGeneration = new Map();
    const componentByPerson = new Map();
    let maxGeneration = 0;
    for (const generation of [...layerIds.keys()].sort((a, b) => a - b)) {
      const components = orderedLayer(layerIds.get(generation), generations)
        .map(ids => ({ ids, generation, families: [], unions: [], width: 0 }));
      componentsByGeneration.set(generation, components);
      maxGeneration = Math.max(maxGeneration, generation);
      for (const component of components) {
        component.ids.forEach(id => componentByPerson.set(id, component));
      }
    }

    for (const union of unions.values()) {
      const parentComponent = componentByPerson.get(union.ownerId);
      if (!parentComponent || union.partners.some(id => !connected.has(id))) continue;
      parentComponent.unions.push(union);
      const family = { union, children: [], width: 0, center: 0 };
      for (const childId of union.children) {
        const childComponent = componentByPerson.get(childId);
        if (childComponent && childComponent !== parentComponent) {
          if (!family.children.includes(childComponent)) family.children.push(childComponent);
        }
      }
      if (family.children.length) parentComponent.families.push(family);
    }

    const componentOrderKey = component => {
      const numbers = component.ids
        .map(id => people.get(id).number)
        .filter(Number.isInteger);
      const values = numbers.length ? numbers : component.ids.map(orderKey);
      return values.reduce((sum, value) => sum + value, 0) / values.length;
    };
    for (const components of componentsByGeneration.values()) {
      for (const component of components) {
        component.families.forEach(family => family.children.sort((a, b) =>
          componentOrderKey(a) - componentOrderKey(b)
        ));
      }
    }

    function measure(component, visiting = new Set()) {
      if (visiting.has(component)) throw new Error("Family relationships contain a cycle.");
      const nextVisiting = new Set(visiting).add(component);
      for (const family of component.families) {
        family.width = family.children.reduce(
          (sum, child) => sum + measure(child, nextVisiting),
          Math.max(0, family.children.length - 1) * SUBTREE_GAP
        );
      }
      const familyWidth = component.families.reduce(
        (sum, family) => sum + family.width,
        Math.max(0, component.families.length - 1) * SUBTREE_GAP
      );
      const ownerGroups = new Map();
      for (const union of component.unions) {
        if (!ownerGroups.has(union.ownerId)) ownerGroups.set(union.ownerId, []);
        ownerGroups.get(union.ownerId).push(union);
      }
      let memberExtent = W / 2;
      for (const [ownerId, ownedUnions] of ownerGroups) {
        const spacing = ownerId === rootId ? FOCUS_GAP : HORIZONTAL_GAP;
        const slots = memberSlots(ownedUnions.length, spacing);
        let left = slots.owner - cardSize(ownerId).width / 2;
        let right = slots.owner + cardSize(ownerId).width / 2;
        ownedUnions.forEach((union, index) => {
          const partnerId = union.partners.find(id => id !== ownerId);
          const center = slots.partners[index];
          left = Math.min(left, center - cardSize(partnerId).width / 2);
          right = Math.max(right, center + cardSize(partnerId).width / 2);
        });
        memberExtent = Math.max(memberExtent, (right - left) / 2);
      }
      component.width = Math.max(2 * memberExtent, familyWidth);
      return component.width;
    }

    const rootComponent = componentByPerson.get(rootId);
    if (!rootComponent) throw new Error('Family tree root "0" is not connected.');
    measure(rootComponent);
    const positions = new Map();

    function place(component, center) {
      const familyWidth = component.families.reduce(
        (sum, family) => sum + family.width,
        Math.max(0, component.families.length - 1) * SUBTREE_GAP
      );
      let familyLeft = center - familyWidth / 2;
      for (const family of component.families) {
        family.center = familyLeft + family.width / 2;
        familyLeft += family.width + SUBTREE_GAP;
      }

      const memberPositions = new Map();
      const ownerGroups = new Map();
      for (const union of component.unions) {
        if (!ownerGroups.has(union.ownerId)) ownerGroups.set(union.ownerId, []);
        ownerGroups.get(union.ownerId).push(union);
      }
      for (const [ownerId, ownedUnions] of ownerGroups) {
        const spacing = ownerId === rootId ? FOCUS_GAP : HORIZONTAL_GAP;
        const slots = memberSlots(ownedUnions.length, spacing);
        memberPositions.set(ownerId, center + slots.owner);
        ownedUnions.forEach((_, index) => {
          const partnerId = ownedUnions[index].partners.find(id => id !== ownerId);
          memberPositions.set(partnerId, center + slots.partners[index]);
        });
      }

      familyLeft = center - familyWidth / 2;
      for (const family of component.families) {
        let childLeft = familyLeft;
        for (const child of family.children) {
          const childCenter = childLeft + child.width / 2;
          place(child, childCenter);
          childLeft += child.width + SUBTREE_GAP;
        }
        familyLeft += family.width + SUBTREE_GAP;
      }

      component.ids.forEach((id, index) => {
        const x = memberPositions.get(id) ??
          center + (index - (component.ids.length - 1) / 2) * HORIZONTAL_GAP;
        positions.set(id, {
          x,
          y: ROOT_Y + component.generation * ROW_GAP,
          generation: component.generation
        });
      });
    }

    place(rootComponent, 0);
    const generationsToPlace = new Set(
      [...positions.values()].map(position => position.generation)
    );
    for (const generation of generationsToPlace) {
      const row = [...positions.entries()]
        .filter(([, position]) => position.generation === generation)
        .sort((a, b) => a[1].x - b[1].x);
      for (let index = 1; index < row.length; index++) {
        const [id, position] = row[index];
        position.x = Math.max(position.x, row[index - 1][1].x + HORIZONTAL_GAP);
        positions.set(id, position);
      }
    }

    const activeAncestorGroups = ancestorGroups
      .filter(ancestorGroup => positions.has(ancestorGroup.childId))
      .sort((a, b) =>
        positions.get(a.childId).x - positions.get(b.childId).x
      );
    const ancestorOffset = activeAncestorGroups.length ? ROW_GAP : 0;
    for (const position of positions.values()) position.y += ancestorOffset;
    activeAncestorGroups.forEach((ancestorGroup, index) => {
      const childPosition = positions.get(ancestorGroup.childId);
      const side = activeAncestorGroups.length === 1
        ? 0
        : index < activeAncestorGroups.length / 2 ? -1 : 1;
      const startX = side < 0
        ? childPosition.x - (ancestorGroup.parentIds.length - 1) * HORIZONTAL_GAP
        : side > 0
          ? childPosition.x
          : childPosition.x - (ancestorGroup.parentIds.length - 1) * HORIZONTAL_GAP / 2;
      ancestorGroup.parentIds.forEach((id, parentIndex) => {
        positions.set(id, {
          x: startX + parentIndex * HORIZONTAL_GAP,
          y: ROOT_Y,
          generation: -1
        });
      });
    });

    const minX = Math.min(...[...positions.values()].map(position => position.x - W / 2));
    const maxX = Math.max(...[...positions.values()].map(position => position.x + W / 2));
    const width = maxX - minX + 48;
    for (const position of positions.values()) position.x += 24 - minX;

    const unionTrack = new Map();
    for (const [id, unionIds] of unionsByPerson) {
      unionIds
        .filter(unionId => connected.has(id))
        .sort()
        .forEach((unionId, index) => {
          unionTrack.set(unionId, Math.max(unionTrack.get(unionId) || 0, index));
        });
    }

    return {
      positions,
      ancestorGroups: activeAncestorGroups,
      unionTrack,
      width,
      height: ROOT_Y + ancestorOffset + maxGeneration * ROW_GAP + H + 40
    };
  }

  const el = (tag, attrs = {}, text = null) => {
    const node = document.createElementNS("http://www.w3.org/2000/svg", tag);
    Object.entries(attrs).forEach(([key, value]) => node.setAttribute(key, value));
    if (text !== null) node.textContent = text;
    return node;
  };

  function connector(group, className, path, unionId) {
    group.append(el("path", {
      d: path,
      class: className,
      "data-union-id": unionId
    }));
  }

  function pathSegments(path) {
    const segments = [];
    let x = 0;
    let y = 0;
    for (const command of path.matchAll(/([MVH])\s*(-?[\d.]+)\s*(-?[\d.]+)?/g)) {
      if (command[1] === "M") {
        x = Number(command[2]);
        y = Number(command[3]);
      } else if (command[1] === "V") {
        const nextY = Number(command[2]);
        segments.push({ x1: x, y1: y, x2: x, y2: nextY });
        y = nextY;
      } else {
        const nextX = Number(command[2]);
        segments.push({ x1: x, y1: y, x2: nextX, y2: y });
        x = nextX;
      }
    }
    return segments;
  }

  function routePartnerLinks(group) {
    const paths = [...group.querySelectorAll(".tree-link,.partner-link")];
    const verticals = paths.flatMap(path =>
      pathSegments(path.getAttribute("d"))
        .filter(segment => segment.x1 === segment.x2)
        .map(segment => ({ ...segment, unionId: path.dataset.unionId }))
    );

    for (const path of paths.filter(node => node.classList.contains("partner-link"))) {
      const segments = pathSegments(path.getAttribute("d"));
      const horizontal = segments.find(segment => segment.y1 === segment.y2);
      if (!horizontal) continue;

      const direction = Math.sign(horizontal.x2 - horizontal.x1);
      const crossings = verticals
        .filter(segment =>
          segment.unionId !== path.dataset.unionId &&
          segment.x1 > Math.min(horizontal.x1, horizontal.x2) &&
          segment.x1 < Math.max(horizontal.x1, horizontal.x2) &&
          horizontal.y1 > Math.min(segment.y1, segment.y2) &&
          horizontal.y1 < Math.max(segment.y1, segment.y2)
        )
        .sort((a, b) => direction * (a.x1 - b.x1));
      if (!crossings.length) continue;

      const start = segments[0];
      const end = segments[segments.length - 1];
      let data = `M ${start.x1} ${start.y1} V ${horizontal.y1}`;
      let currentX = horizontal.x1;
      for (const crossing of crossings) {
        const before = crossing.x1 - direction * CROSSING_JUMP_HALF_WIDTH;
        const after = crossing.x1 + direction * CROSSING_JUMP_HALF_WIDTH;
        const controlY = horizontal.y1 - 2 * CROSSING_JUMP_HEIGHT;
        data += ` H ${before} Q ${crossing.x1} ${controlY} ${after} ${horizontal.y1}`;
        currentX = after;
      }
      if (currentX !== end.x1) data += ` H ${end.x1}`;
      data += ` V ${end.y2}`;
      path.setAttribute("d", data);
      group.append(path);
    }
  }

  function drawConnections(group) {
    for (const union of unions.values()) {
      const [first, second] = union.partners.map(id => layout.positions.get(id));
      if (!first || !second) continue;

      const firstHeight = cardSize(union.partners[0]).height;
      const secondHeight = cardSize(union.partners[1]).height;
      const track = layout.unionTrack.get(union.id) || 0;
      const trackY = first.y + firstHeight + 14 + track * UNION_TRACK_GAP;
      const middleX = (first.x + second.x) / 2;
      connector(
        group,
        "partner-link",
        `M ${first.x} ${first.y + firstHeight} V ${trackY} H ${second.x} V ${second.y + secondHeight}`,
        union.id
      );

      const children = (union.children || [])
        .map(id => ({ id, position: layout.positions.get(id) }))
        .filter(child => child.position)
        .sort((a, b) => a.position.x - b.position.x);
      if (!children.length) continue;

      const branchY = children[0].position.y - 24 - track * UNION_TRACK_GAP;
      connector(group, "tree-link", `M ${middleX} ${trackY} V ${branchY}`, union.id);
      const branchLeft = Math.min(middleX, children[0].position.x);
      const branchRight = Math.max(middleX, children[children.length - 1].position.x);
      connector(group, "tree-link", `M ${branchLeft} ${branchY} H ${branchRight}`, union.id);
      children.forEach(({ position }) => {
        connector(group, "tree-link", `M ${position.x} ${branchY} V ${position.y}`, union.id);
      });
    }
    routePartnerLinks(group);
  }

  function drawAncestorConnections(group) {
    for (const ancestorGroup of layout.ancestorGroups) {
      const parents = ancestorGroup.parentIds
        .map(id => layout.positions.get(id))
        .filter(Boolean)
        .sort((a, b) => a.x - b.x);
      const child = layout.positions.get(ancestorGroup.childId);
      if (!parents.length || !child) continue;

      const trackY = parents[0].y + H + 14;
      if (parents.length > 1) {
        connector(
          group,
          "partner-link",
          `M ${parents[0].x} ${parents[0].y + H} V ${trackY} H ${parents[parents.length - 1].x} V ${parents[parents.length - 1].y + H}`,
          ancestorGroup.id
        );
      }

      const parentCenter = (parents[0].x + parents[parents.length - 1].x) / 2;
      const branchY = child.y - 24;
      connector(
        group,
        "tree-link",
        `M ${parentCenter} ${trackY} V ${branchY} H ${child.x} V ${child.y}`,
        ancestorGroup.id
      );
    }
  }

  function drawPerson(id, position, group) {
    const person = people.get(id);
    const canExpand = expandableIds.has(id);
    const isExpanded = expanded.has(id);
    const isFocusPerson = focusPersonIds.has(id);
    const { width, height } = cardSize(id);
    const familyColor = Number.isInteger(person.number)
      ? colorForPerson(person) || familyLineColors.get(id)
      : null;
    const personName = Number.isInteger(person.number) && !isFocusPerson
      ? `#${person.number} ${person.name}`
      : person.name;
    const personClass = person.isAncestor
      ? "ancestor"
      : isFocusPerson ? "focus" : Number.isInteger(person.number) ? "descendant" : "partner";
    const node = el("g", {
      class: `person-card ${personClass}${canExpand ? " expandable" : ""}`,
      transform: `translate(${position.x - width / 2},${position.y})`,
      "data-person-id": id
    });
    if (familyColor) {
      node.style.setProperty("--family-color", familyColor);
      node.style.setProperty("--family-tint", colorTint(familyColor));
    }
    if (canExpand) {
      node.setAttribute("tabindex", "0");
      node.setAttribute("role", "button");
      node.setAttribute("aria-expanded", String(isExpanded));
      node.setAttribute(
        "aria-label",
        `${personName}. ${isExpanded ? "Collapse" : "Expand"} descendants.`
      );
    }
    node.append(el("rect", { width, height, rx: 12 }));
    if (!isFocusPerson && !person.isAncestor && Number.isInteger(person.number)) {
      node.append(el("text", { x: 13, y: 19, class: "person-number" }, `#${person.number}`));
    } else if (!isFocusPerson && !person.isAncestor) {
      node.append(el("text", { x: 13, y: 19, class: "partner-tag" }, "PARTNER"));
    }
    if (canExpand) {
      node.append(el(
        "text",
        { x: width - 18, y: 24, class: "expansion-indicator", "text-anchor": "middle" },
        isExpanded ? "−" : "+"
      ));
    }
    const textX = isFocusPerson ? 16 : 13;
    const nameY = isFocusPerson ? 54 : person.isAncestor ? 48 : 43;
    const yearsY = isFocusPerson ? 82 : person.isAncestor ? 68 : 64;
    node.append(el("text", { x: textX, y: nameY, class: "person-name" }, person.name));
    if (years(person)) node.append(el("text", { x: textX, y: yearsY, class: "person-years" }, years(person)));
    if (canExpand) {
      node.addEventListener("keydown", event => {
        if (event.key === "Enter" || event.key === " ") {
          if (event.repeat) return;
          event.preventDefault();
          toggleExpansion(id);
        }
      });
    }
    group.append(node);
  }

  function toggleExpansion(id) {
    if (!expandableIds.has(id)) return;
    const position = cardCenterInViewport(id);
    if (expanded.has(id)) expanded.delete(id);
    else expanded.add(id);
    render();
    if (position) keepCardInViewportPosition(id, position);
    canvas.querySelector(`.person-card[data-person-id="${CSS.escape(id)}"]`)?.focus({
      preventScroll: true
    });
  }

  function showAll() {
    expandableIds.forEach(id => expanded.add(id));
    render();
    resetView();
  }

  function returnToDefaultView() {
    expanded.clear();
    expanded.add(rootId);
    search.value = "";
    buildDirectory();
    directory.closest("details").open = false;
    render();
    resetView();
  }

  function render() {
    layout = calculate();
    const group = el("g");
    canvas.replaceChildren(group);
    drawConnections(group);
    drawAncestorConnections(group);
    for (const [id, position] of layout.positions) drawPerson(id, position, group);

    const width = Math.max(1, viewport.clientWidth);
    const height = Math.max(1, viewport.clientHeight);
    svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
    svg.setAttribute("width", width);
    svg.setAttribute("height", height);
    transform();
  }

  function transform() {
    canvas.setAttribute("transform", `translate(${tx} ${ty}) scale(${scale})`);
    $("#zoomLevel").textContent = `${Math.round(scale * 100)}%`;
  }

  function focus(id) {
    const position = cardCenterInViewport(id);
    if (!position) return;
    const rect = viewport.getBoundingClientRect();
    tx += rect.width / 2 - position.x;
    ty += rect.height / 2 - position.y;
    transform();
  }

  function cardCenterInViewport(id) {
    const node = canvas.querySelector(`.person-card[data-person-id="${CSS.escape(id)}"]`);
    if (!node) return null;
    const matrix = node.getCTM();
    if (!matrix) return null;
    const { width, height } = cardSize(id);
    return {
      x: matrix.e + matrix.a * width / 2,
      y: matrix.f + matrix.d * height / 2
    };
  }

  function keepCardInViewportPosition(id, position) {
    const nextPosition = cardCenterInViewport(id);
    if (!nextPosition) return;
    tx += position.x - nextPosition.x;
    ty += position.y - nextPosition.y;
    transform();
  }

  function expandAncestors(id) {
    const pending = [id];
    const visited = new Set();
    while (pending.length) {
      const childId = pending.pop();
      if (visited.has(childId)) continue;
      visited.add(childId);
      for (const parentId of parentsByChild.get(childId) || []) {
        expanded.add(parentId);
        pending.push(parentId);
      }
    }
  }

  function buildDirectory(query = "") {
    directory.replaceChildren();
    const normalized = query.trim().toLowerCase();
    const entries = [
      ...descendants
        .filter(person => `${person.number} ${person.name}`.toLowerCase().includes(normalized))
        .map(person => ({ id: person.id, person, ownerId: null, owner: null })),
      ...partnerEntries.filter(({ person, owner }) =>
        `${person.name} ${owner.number} ${owner.name}`.toLowerCase().includes(normalized)
      )
    ];

    entries.forEach(entry => {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "directory-item";
      const number = document.createElement("span");
      number.className = "directory-number";
      number.textContent = `#${entry.owner?.number ?? entry.person.number}`;
      const name = document.createElement("span");
      name.className = "directory-name";
      name.textContent = entry.owner
        ? `${entry.person.name} (partner of ${entry.owner.name})`
        : entry.person.name;
      button.append(number, name);
      button.addEventListener("click", () => {
        const ancestorId = entry.ownerId || entry.id;
        expandAncestors(ancestorId);
        if (entry.ownerId) expanded.add(entry.ownerId);
        scale = Math.max(scale, 0.85);
        render();
        focus(entry.id);
        directory.closest("details").open = false;
      });
      directory.append(button);
    });

    if (!directory.children.length) {
      const empty = document.createElement("p");
      empty.className = "empty";
      empty.textContent = "No matching family members.";
      directory.append(empty);
    }
  }

  function zoom(next, anchorX = viewport.clientWidth / 2, anchorY = viewport.clientHeight / 2) {
    const nextScale = Math.min(2.2, Math.max(0.03, next));
    const ratio = nextScale / scale;
    tx = anchorX - (anchorX - tx) * ratio;
    ty = anchorY - (anchorY - ty) * ratio;
    scale = nextScale;
    transform();
  }

  function resetView() {
    scale = Math.min(1, viewport.clientWidth / layout.width, viewport.clientHeight / layout.height);
    tx = (viewport.clientWidth - layout.width * scale) / 2;
    ty = (viewport.clientHeight - layout.height * scale) / 2;
    transform();
  }

  $("#zoomIn").addEventListener("click", () => zoom(scale * 1.18));
  $("#zoomOut").addEventListener("click", () => zoom(scale / 1.18));
  $("#showAll").addEventListener("click", showAll);
  $("#resetView").addEventListener("click", returnToDefaultView);
  search.addEventListener("input", () => buildDirectory(search.value));

  viewport.addEventListener("pointerdown", event => {
    dragging = true;
    dragged = false;
    pointerStart = { x: event.clientX, y: event.clientY };
    pointerTargetId = event.target.closest(".person-card.expandable")?.dataset.personId || null;
    dragStart = { x: event.clientX - tx, y: event.clientY - ty };
    viewport.classList.add("dragging");
    viewport.setPointerCapture(event.pointerId);
  });
  viewport.addEventListener("pointermove", event => {
    if (!dragging) return;
    if (
      pointerStart &&
      Math.hypot(event.clientX - pointerStart.x, event.clientY - pointerStart.y) > 4
    ) {
      dragged = true;
    }
    tx = event.clientX - dragStart.x;
    ty = event.clientY - dragStart.y;
    transform();
  });
  function stopDragging(event) {
    if (event.type === "pointerup" && !dragged && pointerTargetId) {
      pointerClickId = pointerTargetId;
      toggleExpansion(pointerTargetId);
      setTimeout(() => {
        pointerClickId = null;
      }, 0);
    }
    dragging = false;
    pointerStart = null;
    pointerTargetId = null;
    viewport.classList.remove("dragging");
    if (dragged) {
      setTimeout(() => {
        dragged = false;
      }, 0);
    }
  }
  viewport.addEventListener("click", event => {
    if (dragged) return;
    const node = event.target.closest(".person-card.expandable");
    if (!node) return;
    if (pointerClickId === node.dataset.personId) {
      pointerClickId = null;
      return;
    }
    toggleExpansion(node.dataset.personId);
  });
  viewport.addEventListener("pointerup", stopDragging);
  viewport.addEventListener("pointercancel", stopDragging);
  viewport.addEventListener("wheel", event => {
    event.preventDefault();
    const rect = viewport.getBoundingClientRect();
    zoom(scale * (event.deltaY < 0 ? 1.08 : 1 / 1.08), event.clientX - rect.left, event.clientY - rect.top);
  }, { passive: false });
  window.addEventListener("resize", () => {
    render();
    resetView();
  });

  $("#familyTitle").textContent = FAMILY.familyName || "Family Tree";
  document.title = `${FAMILY.familyName || "Family"} · Family Tree`;
  render();
  buildDirectory();
  requestAnimationFrame(resetView);
}

const unlockForm = document.querySelector("#unlockForm");
const unlockPanel = document.querySelector("#unlockPanel");
const familyApp = document.querySelector("#familyApp");
const passwordInput = document.querySelector("#password");
const unlockButton = document.querySelector("#unlockButton");
const unlockStatus = document.querySelector("#unlockStatus");
const rememberBrowser = document.querySelector("#rememberBrowser");
const forgetBrowserButton = document.querySelector("#forgetBrowser");
const browserStatus = document.querySelector("#browserStatus");

unlockForm.addEventListener("submit", async event => {
  event.preventDefault();
  unlockButton.disabled = true;
  setUnlockStatus("Unlocking…");

  let family;
  let key;
  try {
    ({ family, key } = await loadFamily(passwordInput.value));
  } catch (error) {
    console.error("Could not unlock family data.", error);
    setUnlockStatus(error instanceof Error
      ? error.message
      : "Could not unlock family data.", true);
    passwordInput.value = "";
    unlockButton.disabled = false;
    passwordInput.focus();
    return;
  }

  if (rememberBrowser.checked) {
    try {
      await saveRememberedKey(key);
    } catch (error) {
      console.error("Could not remember access in this browser.", error);
      setUnlockStatus(
        "Could not remember this browser. Uncheck the remember option and try again.",
        true
      );
      unlockButton.disabled = false;
      passwordInput.focus();
      return;
    }
  }

  passwordInput.value = "";
  showFamily(family);
  unlockButton.disabled = false;
});

forgetBrowserButton.addEventListener("click", async () => {
  forgetBrowserButton.disabled = true;
  browserStatus.hidden = true;
  browserStatus.textContent = "";
  try {
    await deleteRememberedKey();
    familyApp.hidden = true;
    unlockPanel.hidden = false;
    document.title = "Family Tree";
    setUnlockStatus("Remembered access has been removed from this browser.");
    passwordInput.focus();
  } catch (error) {
    console.error("Could not forget remembered family access.", error);
    browserStatus.textContent = "Could not remove the saved key from this browser.";
    browserStatus.hidden = false;
  } finally {
    forgetBrowserButton.disabled = false;
  }
});

restoreRememberedFamily();
