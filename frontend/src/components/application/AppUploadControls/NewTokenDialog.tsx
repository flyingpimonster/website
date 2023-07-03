import { Dialog, Transition } from "@headlessui/react"
import { Fragment, FunctionComponent, ReactElement, useState } from "react"
import { useTranslation } from "react-i18next"
import {
  NewTokenResponse,
  Repo,
  createUploadToken,
} from "src/asyncs/upload_tokens"
import Button from "src/components/Button"
import Spinner from "src/components/Spinner"

interface Props {
  app_id: string
  repo: Repo
  visible: boolean
  cancel: () => void
  created?: (response: NewTokenResponse) => void
}

const NewTokenDialog: FunctionComponent<Props> = ({
  app_id,
  repo,
  visible,
  cancel,
  created,
}) => {
  const { t } = useTranslation()

  const [state, setState] = useState<"new" | "pending" | "copy-token">("new")

  const title = repo === "beta" ? t("new-beta-token") : t("new-stable-token")

  const [comment, setComment] = useState("")
  const [scopes, setScopes] = useState(["build", "upload", "publish"])
  const [token, setToken] = useState("")

  const createToken = async () => {
    setState("pending")
    const response = await createUploadToken(app_id, comment, scopes, [repo])
    setToken(response.token)
    setState("copy-token")
    created?.(response)
  }

  const setScope = (scope: string, checked: boolean) => {
    if (checked) {
      if (!scopes.includes(scope)) {
        setScopes([...scopes, scope])
      }
    } else {
      setScopes(scopes.filter((s) => s !== scope))
    }
  }

  const hideDialog = () => {
    setState("new")
    setComment("")
    cancel()
  }

  let content: ReactElement

  switch (state) {
    case "new":
      content = (
        <>
          <input
            className="w-full rounded-xl border border-flathub-sonic-silver p-3 dark:border-flathub-spanish-gray"
            placeholder={t("token-name")}
            value={comment}
            onInput={(e) => setComment((e.target as HTMLInputElement).value)}
          />

          <div>
            <h4>{t("scopes")}</h4>
            {["build", "upload", "publish"].map((scope) => (
              <div key={scope}>
                <input
                  id={`scope-${scope}`}
                  type="checkbox"
                  className="mr-2"
                  checked={scopes.includes(scope)}
                  onChange={(event) => setScope(scope, event.target.checked)}
                  disabled={scope === "build"}
                />
                <label htmlFor={`scope-${scope}`}>{t(`scope-${scope}`)}</label>
              </div>
            ))}
          </div>

          <div className="mt-3 grid grid-cols-2 gap-6">
            <Button
              className="col-start-1"
              onClick={hideDialog}
              variant="secondary"
              aria-label={t("cancel")}
              title={t("cancel")}
            >
              {t("cancel")}
            </Button>
            <Button
              className="col-start-2"
              onClick={createToken}
              variant={"primary"}
              disabled={!comment}
            >
              {t("create-token")}
            </Button>
          </div>
        </>
      )
      break
    case "pending":
      content = <Spinner size="m" />
      break
    case "copy-token":
      content = (
        <>
          <p>{t("token-created")}</p>
          <code className="break-all">{token}</code>
        </>
      )
      break
  }

  return (
    <Transition appear show={visible} as={Fragment}>
      <Dialog as="div" className="z-20" onClose={hideDialog}>
        <div className="fixed inset-0 bg-black/30" aria-hidden="true" />

        <div className="fixed inset-0 flex items-center justify-center p-4">
          <Dialog.Panel className="inline-flex w-full flex-col justify-center space-y-6 rounded-xl bg-flathub-gainsborow p-14 shadow-md dark:bg-flathub-dark-gunmetal md:w-2/3 lg:w-1/2">
            <Dialog.Title className="m-0">{title}</Dialog.Title>

            {content}
          </Dialog.Panel>
        </div>
      </Dialog>
    </Transition>
  )
}

export default NewTokenDialog
