<script lang="ts">
  import type { KeyboardEventHandler } from 'svelte/elements';

  let {
    id,
    dropdownItems,
    placeholder,
    value = $bindable()
  }: {
    id: string;
    dropdownItems: string[];
    placeholder: string;
    value: string | undefined;
  } = $props();

  let highlightedIdx: number = $state(0);
  let showDropdown: boolean = $state(false);

  let inputValue: string = $derived(value ?? '');

  let sortedropdownItems: string[] = $derived(dropdownItems.sort((a, b) => a.localeCompare(b)));
  let filteredDropdownItems: string[] = $derived(
    sortedropdownItems.filter((dropdownItem) => getInputValueIdxInDropdownItem(dropdownItem) >= 0)
  );
  let filteredDropdownItemsDisplayData = $derived(
    filteredDropdownItems.map((dropdownItem) => {
      const inputValueIdx = getInputValueIdxInDropdownItem(dropdownItem);
      if (inputValueIdx === -1) {
        // should never happen
        return {
          value: dropdownItem,
          displayData: { preInputValue: dropdownItem, inputValue: '', postInputValue: '' }
        };
      }
      return {
        value: dropdownItem,
        displayData: {
          preInputValue: dropdownItem.substring(0, inputValueIdx),
          inputValue: dropdownItem.substring(inputValueIdx, inputValueIdx + inputValue.length),
          postInputValue: dropdownItem.substring(inputValueIdx + inputValue.length)
        }
      };
    })
  );

  $effect(() => {
    // reset highlightedIdx whenever inputValue changes
    inputValue;
    highlightedIdx = 0;
  });
  $effect(() => {
    const highlightedDropdownItem = dropdown.childNodes[highlightedIdx];
    if (highlightedDropdownItem instanceof HTMLElement) {
      highlightedDropdownItem.scrollIntoView();
    }
  });

  let searchInput: HTMLInputElement;
  let dropdown: HTMLDivElement;

  const getInputValueIdxInDropdownItem = (dropdownItem: string) =>
    dropdownItem.toLowerCase().indexOf(inputValue.toLowerCase());

  const onkeydown: KeyboardEventHandler<any> = (e) => {
    showDropdown = true;
    switch (e.key) {
      case 'ArrowDown':
        if (highlightedIdx < filteredDropdownItems.length - 1) {
          highlightedIdx++;
        }
        e.preventDefault();
        return;
      case 'ArrowUp':
        if (highlightedIdx > 0) {
          highlightedIdx--;
        }
        e.preventDefault();
        return;
      case 'Enter':
        setDropdownItem(filteredDropdownItems[highlightedIdx]);
        return;
      case 'Escape':
        showDropdown = false;
        return;
    }
  };

  const setDropdownItem = (dropdownItem: string) => {
    value = dropdownItem;
    showDropdown = false;
    searchInput.focus();
  };

  const eventTargetInDropdown = (eventTarget: EventTarget | null) =>
    eventTarget instanceof HTMLElement && eventTarget.parentElement === dropdown;
</script>

<div class="autocomplete">
  <input
    {id}
    type="text"
    {placeholder}
    bind:this={searchInput}
    bind:value
    required
    on:keydown={onkeydown}
    on:focus={(e) => {
      if (!eventTargetInDropdown(e.relatedTarget)) {
        showDropdown = true;
      }
    }}
    on:blur={(e) => {
      if (!eventTargetInDropdown(e.relatedTarget)) {
        showDropdown = false;
      }
    }}
  />
  <div
    class="dropdown"
    bind:this={dropdown}
    hidden={filteredDropdownItemsDisplayData.length === 0 || !showDropdown}
  >
    {#each filteredDropdownItemsDisplayData as dropdownItemDisplayData, i}
      <div
        class="dropdown-item"
        class:highlighted-dropdown-item={i === highlightedIdx}
        on:click={() => setDropdownItem(dropdownItemDisplayData.value)}
        on:keydown={onkeydown}
        role="button"
        tabindex={i}
      >
        <span>{dropdownItemDisplayData.displayData.preInputValue}</span><span>
          <strong>{dropdownItemDisplayData.displayData.inputValue}</strong>
        </span><span>{dropdownItemDisplayData.displayData.postInputValue}</span>
      </div>
    {/each}
  </div>
</div>

<style>
  div.autocomplete {
    position: relative;
    display: inline-block;
    width: 100%;

    input {
      width: 100%;
      box-sizing: border-box;
      padding: 10px 12px;
      border: 1px solid #cecccc;
      border-radius: 4px;
      font-size: 15px;

      &:focus {
        outline: none;
        border-color: #1279c5;
      }
    }

    .dropdown {
      position: absolute;
      top: 40px;
      max-height: 320px;
      overflow-y: scroll;
      border: 1px solid #cecccc;
      font-size: 15px;

      .dropdown-item {
        border-bottom: 1px solid #cecccc;
        z-index: 99;
        top: 100%;
        padding: 10px 12px;
        cursor: pointer;
        background-color: #fff;

        &:hover {
          background-color: color-mix(in srgb, #1279c5 80%, white);
          color: white;
        }

        &.highlighted-dropdown-item {
          background-color: #1279c5;
          color: #ffffff;
        }
      }
    }
  }
</style>
