<script>
    import {onMount} from "svelte";
    import {studentDetails, submitStudentDetails, customAgreementUrl} from "./api";
    import {getParameterByName} from "./utils/queryParameters";
    import nl from "./locale/nl";
    import en from "./locale/en";

    const FIELD_ORDER = ["naam", "adres", "email", "telefoon", "opleiding", "studentnummer"];

    const lang = (getParameterByName("lang") || navigator.language || "nl").toLowerCase().substring(0, 2);
    const messages = lang === "en" ? en : nl;

    const correlationID = getParameterByName("correlationID");

    // stage: loading -> form -> submitting -> ready | error
    let stage = "loading";
    let missingFields = [];
    let values = {};
    let redirectUrl = null;

    const submit = () => {
        stage = "submitting";
        submitStudentDetails({correlationID, ...values})
            .then(res => {
                redirectUrl = res.redirect;
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
                missingFields = FIELD_ORDER.filter(field => res.fields[field] && res.fields[field].missing);
                if (missingFields.length === 0) {
                    //Nothing to ask - submit straight away so the student still gets a download link
                    submit();
                } else {
                    missingFields.forEach(field => values[field] = "");
                    stage = "form";
                }
            })
            .catch(() => {
                stage = "error";
            });
    });

    $: allFilled = missingFields.every(field => values[field] && values[field].trim().length > 0);
</script>

<style lang="scss">
    :global(body) {
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        background: #f5f7f8;
        margin: 0;
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

<div class="page">
    {#if stage === "loading" || stage === "submitting"}
        <p class="note">{stage === "submitting" ? messages.submitting : messages.loading}</p>
    {:else if stage === "error"}
        <p class="error">{messages.error}</p>
    {:else if stage === "form"}
        <h1>{messages.title}</h1>
        <p class="intro">{messages.intro}</p>
        <form on:submit|preventDefault={submit}>
            {#each missingFields as field (field)}
                <div class="field">
                    <label for={field}>{messages.labels[field]}</label>
                    <input id={field}
                           type={field === "email" ? "email" : "text"}
                           placeholder={messages.placeholders[field]}
                           bind:value={values[field]}
                           required/>
                </div>
            {/each}
            <button type="submit" disabled={!allFilled}>
                {messages.submit}
            </button>
        </form>
    {:else if stage === "ready"}
        <h1>{messages.readyTitle}</h1>
        <p class="intro">{messages.readyIntro}</p>
        <div class="actions">
            <a class="button" href={customAgreementUrl(correlationID)} target="_blank" rel="noopener">
                {messages.download}
            </a>
            <a class="button secondary" href={redirectUrl}>
                {messages.continue}
            </a>
        </div>
    {/if}
</div>
