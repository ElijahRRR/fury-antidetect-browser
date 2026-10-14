// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Bogdan Shapovalov and the Fury authors

import { useI18n } from "../i18n";

/** The name at the top of every screen before signing in, with the version
 *  under it.
 *
 *  The version is there for the screenshot someone sends when they are stuck.
 *  A member waiting to be let in had no verification code on her screen
 *  (14.10.2026), and the only way to tell she was on a build from before the
 *  code existed was to recognise the wording of an old sentence. */
export function Brand({ version }: { version?: string }) {
  const { t } = useI18n();
  return (
    <>
      <h1>Fury</h1>
      {version && <p className="loginVersion">{t("auth.version", { version })}</p>}
    </>
  );
}
