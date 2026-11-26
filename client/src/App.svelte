<script>
    import {onMount} from "svelte";
    import {studentDetails, submitStudentDetails, customAgreementUrl, features, educationItemNames} from "./api";
    import {getParameterByName} from "./utils/queryParameters";
    import nl from "./locale/nl";
    import en from "./locale/en";
    import Autocomplete from './Autocomplete.svelte';

    const FIELD_ORDER = ["naam", "adres", "email", "telefoon", "opleiding", "studentnummer"];

    const lang = (getParameterByName("lang") || localStorage.getItem("lang") || navigator.language || "nl").toLowerCase().substring(0, 2);
    const messages = lang === "en" ? en : nl;

    const changeLanguage = newLang => () => {
        localStorage.setItem("lang", newLang);
        const urlSearchParams = new URLSearchParams(window.location.search);
        urlSearchParams.set("lang", newLang);
        window.location.search = urlSearchParams.toString();
    };

    const correlationID = getParameterByName("correlationID");

    // stage: loading -> form -> submitting -> ready | error
    let stage = "loading";
    let displayedFields = [];
    let values = {};
    let catalogUrl = null;
    let brokerUrl = null;
    let downloadClicked = false;
    let educationNames = []

    // load educationItemNames to show in the autocomplete control,
    // if it fails we don't care too much, the control will still function as a regular input
    educationItemNames()
        .then(newEducationNames => { educationNames = newEducationNames })
        .catch(() => {});

    features()
        .then(res => {
            catalogUrl = res.catalogUrl;
            brokerUrl = res.brokerUrl;
        })
        .catch(() => {});

    const submit = () => {
        stage = "submitting";
        submitStudentDetails({correlationID, ...values})
            .then(() => {
                stage = "ready";
            })
            .catch(() => {
                stage = "error";
            });
    };

    onMount(() => {
        if (!correlationID) {
            stage = "error";
            return;
        }
        studentDetails(correlationID)
            .then(res => {
                const missingFields = FIELD_ORDER.filter(field => res.fields[field] && res.fields[field].missing);
                //The name should always be editable, even when it's already known (e.g. from
                //SURFconext), since that source isn't necessarily the name the student wants to use.
                displayedFields = missingFields.includes("naam") ? missingFields : ["naam", ...missingFields];
                displayedFields.forEach(field => {
                    const known = res.fields[field] && res.fields[field].value;
                    values[field] = known || "";
                });
                stage = "form";
            })
            .catch(() => {
                stage = "error";
            });
    });

    $: allFilled = displayedFields.every(field => values[field] && values[field].trim().length > 0);
</script>

<style lang="scss">
    :global(body) {
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        background: #f5f7f8;
        margin: 0;
    }

    .eu-header {
        width: 100%;
        display: flex;
        background-color: #004C97;
        padding: 12px 0;

        @media (max-width: 1000px) {
            padding: 12px 20px;
        }

        .eu-header-inner {
            width: 990px;
            color: white;
            margin: 0 auto;
            display: flex;
            align-items: center;

            .left {
                font-size: 26px;
                font-weight: 500;
                margin: 0;
            }

            .language-switcher {
                margin-left: auto;

                ul {
                    list-style: none;
                    margin: 0;
                    padding: 0;

                    li {
                        display: inline-block;
                        padding: 0 4px;

                        a {
                            color: #a9c6e6;
                            text-decoration: none;
                            font-weight: normal;
                        }
                    }

                    li.active a {
                        color: white;
                        font-weight: 500;
                        cursor: default;
                    }
                }
            }

            a.right {
                margin-left: 16px;
                color: white;
                text-decoration: none;
            }
        }
    }

    .page {
        max-width: 520px;
        margin: 40px auto;
        padding: 32px;
        background: white;
        border-radius: 8px;
        box-shadow: 0 1px 4px rgba(0, 0, 0, 0.1);
    }

    h1 {
        font-size: 22px;
        margin: 0 0 8px 0;
        color: #1a1a1a;
    }

    p.intro {
        color: #5d6872;
        margin-bottom: 24px;
        line-height: 1.5;
    }

    label {
        display: block;
        font-weight: 500;
        margin-bottom: 6px;
        color: #1a1a1a;
    }

    .field {
        margin-bottom: 20px;
    }

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

    .actions {
        display: flex;
        gap: 12px;
        align-items: center;
        margin-top: 8px;
    }

    button, a.button {
        padding: 10px 24px;
        background-color: #1279c5;
        border: none;
        border-radius: 4px;
        color: white;
        font-weight: 500;
        font-size: 15px;
        cursor: pointer;
        text-decoration: none;
        display: inline-block;
        box-sizing: border-box;

        &:disabled {
            cursor: not-allowed;
            background-color: #efefef;
            color: #ababab;
        }

        &:hover:not(:disabled) {
            background-color: #225fb1;
        }

        &.secondary {
            background-color: white;
            color: #5d6872;
            border: 1px solid #5d6872;

            &:hover {
                background-color: #f8f8f8;
                color: black;
            }
        }
    }

    .error {
        color: #bd0202;
    }

    .note {
        color: #5d6872;
    }
</style>

{#if stage === "form" || stage === "ready"}
    <div class="eu-header">
        <div class="eu-header-inner">
            <h2 class="left">{messages.header}</h2>
            <div class="language-switcher">
                <ul>
                    <li class={lang === "nl" ? "active" : "non_active"}>
                        <a href="?lang=nl" on:click|preventDefault={changeLanguage("nl")}>NL</a>
                    </li>
                    <li class={lang === "en" ? "active" : "non_active"}>
                        <a href="?lang=en" on:click|preventDefault={changeLanguage("en")}>EN</a>
                    </li>
                </ul>
            </div>
            {#if catalogUrl}
                <a class="right" href={catalogUrl}>{messages.backToEduXchange}</a>
            {/if}
        </div>
    </div>
{/if}
<div class="page">
    {#if stage === "loading" || stage === "submitting"}
        <p class="note">{stage === "submitting" ? messages.submitting : messages.loading}</p>
    {:else if stage === "error"}
        <p class="error">{messages.error}</p>
    {:else if stage === "form"}
        <h1>{messages.title}</h1>
        <p class="intro">{messages.intro}</p>
        <form on:submit|preventDefault={submit}>
            {#each displayedFields as field (field)}
                <div class="field">
                    <label for={field}>{messages.labels[field]}</label>
                    {#if field === 'opleiding'}
                        <Autocomplete
                            id={field}
                            dropdownItems={educationNames}
                            placeholder={messages.placeholders[field]}
                            bind:value={values[field]}
                        />
                    {:else}
                        <input
                            id={field}
                            type={field === 'email' ? 'email' : 'text'}
                            placeholder={messages.placeholders[field]}
                            bind:value={values[field]}
                            required
                        />
                    {/if}
                </div>
            {/each}
            <button type="submit" disabled={!allFilled}>
                {messages.submit}
            </button>
        </form>
    {:else if stage === "ready"}
        <h1>{messages.readyTitle}</h1>
        <p class="intro">{messages.readyIntro}</p>
        <ul>
            {#each messages.readyToDos as todo}
                <li>{todo}</li>
            {/each}
        </ul>
        <div class="actions">
            <a class="button" href={customAgreementUrl(correlationID)} target="_blank" rel="noopener"
               on:click={() => downloadClicked = true}>
                {messages.download}
            </a>
            <button type="button" class="button secondary" disabled={!downloadClicked}
                    on:click={() => window.location.href = `${brokerUrl}/?step=almost&correlationID=${encodeURIComponent(correlationID)}`}>
                {messages.continue}
            </button>
        </div>
    {/if}
</div>
