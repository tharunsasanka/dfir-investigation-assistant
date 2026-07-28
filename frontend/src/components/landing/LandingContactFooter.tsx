import {
  ArrowRight,
  Code2,
  Github,
  Linkedin,
  ShieldCheck,
} from 'lucide-react'
import {
  Link,
} from 'react-router-dom'

const githubUrl =
  'https://github.com/tharunsasanka'

const repositoryUrl =
  'https://github.com/tharunsasanka/dfir-investigation-assistant'

const linkedInUrl =
  'https://www.linkedin.com/in/tharun-sasanka-8280ba2b4/'

export function LandingContactFooter() {
  return (
    <>
      <section
        id="contact"
        className="border-t border-white/10 py-24"
      >
        <div className="mx-auto max-w-7xl px-6">
          <div className="glass relative overflow-hidden rounded-3xl p-7 sm:p-10 lg:p-12">
            <div className="absolute -right-20 -top-20 h-72 w-72 rounded-full bg-cyan/10 blur-[110px]" />
            <div className="absolute -bottom-28 left-1/4 h-64 w-64 rounded-full bg-blue-500/10 blur-[110px]" />

            <div className="relative grid gap-10 lg:grid-cols-[1fr_420px] lg:items-center">
              <div>
                <p className="text-sm font-medium uppercase tracking-[0.24em] text-cyan">
                  Contact us
                </p>

                <h2 className="mt-4 max-w-3xl text-3xl font-bold tracking-tight text-white sm:text-4xl">
                  Connect for cybersecurity research, collaboration and software development
                </h2>

                <p className="mt-5 max-w-2xl text-base leading-7 text-slate-400 sm:text-lg">
                  The DFIR Investigation Assistant was developed as
                  an evidence-grounded digital forensics platform for
                  incident investigation, academic research and
                  security-focused software development.
                </p>

                <div className="mt-8 flex flex-wrap gap-3">
                  <a
                    href={linkedInUrl}
                    target="_blank"
                    rel="noreferrer"
                    className="inline-flex items-center gap-2 rounded-xl bg-cyan px-5 py-3 font-semibold text-slate-950 transition hover:-translate-y-0.5 hover:brightness-110"
                  >
                    <Linkedin size={18} />
                    Contact on LinkedIn
                  </a>

                  <a
                    href={repositoryUrl}
                    target="_blank"
                    rel="noreferrer"
                    className="inline-flex items-center gap-2 rounded-xl border border-white/15 px-5 py-3 font-semibold text-slate-200 transition hover:-translate-y-0.5 hover:border-cyan/40 hover:text-cyan"
                  >
                    <Github size={18} />
                    View Project Repository
                  </a>
                </div>
              </div>

              <div className="rounded-3xl border border-white/10 bg-[#091524]/80 p-6">
                <div className="flex items-start gap-4">
                  <div className="rounded-2xl bg-cyan/10 p-3 text-cyan">
                    <Code2 size={24} />
                  </div>

                  <div>
                    <p className="text-xl font-semibold text-white">
                      Tharun Sasanka
                    </p>

                    <p className="mt-1 text-sm text-cyan">
                      Cybersecurity and Full-Stack Development
                    </p>
                  </div>
                </div>

                <div className="mt-6 space-y-4 border-t border-white/10 pt-6">
                  <a
                    href={linkedInUrl}
                    target="_blank"
                    rel="noreferrer"
                    className="flex items-center justify-between gap-4 rounded-2xl border border-white/10 bg-white/[0.03] p-4 transition hover:border-cyan/30 hover:bg-white/[0.05]"
                  >
                    <div className="flex items-center gap-3">
                      <Linkedin
                        size={19}
                        className="text-cyan"
                      />

                      <div>
                        <p className="text-sm font-medium text-white">
                          LinkedIn
                        </p>

                        <p className="mt-1 text-xs text-slate-500">
                          Professional profile and contact
                        </p>
                      </div>
                    </div>

                    <ArrowRight
                      size={17}
                      className="text-slate-500"
                    />
                  </a>

                  <a
                    href={githubUrl}
                    target="_blank"
                    rel="noreferrer"
                    className="flex items-center justify-between gap-4 rounded-2xl border border-white/10 bg-white/[0.03] p-4 transition hover:border-cyan/30 hover:bg-white/[0.05]"
                  >
                    <div className="flex items-center gap-3">
                      <Github
                        size={19}
                        className="text-cyan"
                      />

                      <div>
                        <p className="text-sm font-medium text-white">
                          GitHub
                        </p>

                        <p className="mt-1 text-xs text-slate-500">
                          Projects and source code
                        </p>
                      </div>
                    </div>

                    <ArrowRight
                      size={17}
                      className="text-slate-500"
                    />
                  </a>

                  <div className="rounded-2xl border border-cyan/15 bg-cyan/[0.05] p-4">
                    <p className="text-sm font-medium text-white">
                      Project enquiries
                    </p>

                    <p className="mt-2 text-xs leading-5 text-slate-400">
                      Use LinkedIn for collaboration, research,
                      development and DFIR project enquiries.
                    </p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      <footer className="border-t border-white/10 bg-[#050d18]/80">
        <div className="mx-auto max-w-7xl px-6 py-10">
          <div className="flex flex-col gap-10 lg:flex-row lg:items-start lg:justify-between">
            <div className="max-w-md">
              <div className="flex items-center gap-3">
                <div className="rounded-xl bg-cyan/10 p-2.5 text-cyan">
                  <ShieldCheck size={21} />
                </div>

                <div>
                  <p className="font-semibold text-white">
                    DFIR Investigation Assistant
                  </p>

                  <p className="text-xs text-slate-500">
                    Evidence-grounded forensic analysis
                  </p>
                </div>
              </div>

              <p className="mt-5 text-sm leading-6 text-slate-500">
                A unified platform for evidence management,
                forensic analysis, event correlation, timeline
                reconstruction, AI-assisted investigation and
                evidence-linked reporting.
              </p>
            </div>

            <div className="grid gap-8 sm:grid-cols-3">
              <div>
                <p className="text-sm font-semibold text-white">
                  Platform
                </p>

                <div className="mt-4 grid gap-3 text-sm text-slate-500">
                  <a
                    href="#workflow"
                    className="transition hover:text-cyan"
                  >
                    Workflow
                  </a>

                  <a
                    href="#capabilities"
                    className="transition hover:text-cyan"
                  >
                    Capabilities
                  </a>

                  <a
                    href="#evidence"
                    className="transition hover:text-cyan"
                  >
                    Evidence
                  </a>

                  <a
                    href="#interface"
                    className="transition hover:text-cyan"
                  >
                    Interface
                  </a>
                </div>
              </div>

              <div>
                <p className="text-sm font-semibold text-white">
                  Trust
                </p>

                <div className="mt-4 grid gap-3 text-sm text-slate-500">
                  <a
                    href="#trust"
                    className="transition hover:text-cyan"
                  >
                    AI traceability
                  </a>

                  <a
                    href="#security"
                    className="transition hover:text-cyan"
                  >
                    Security
                  </a>

                  <a
                    href="#contact"
                    className="transition hover:text-cyan"
                  >
                    Contact us
                  </a>
                </div>
              </div>

              <div>
                <p className="text-sm font-semibold text-white">
                  Access
                </p>

                <div className="mt-4 grid gap-3 text-sm text-slate-500">
                  <Link
                    to="/login"
                    className="transition hover:text-cyan"
                  >
                    Analyst sign in
                  </Link>

                  <Link
                    to="/dashboard"
                    className="transition hover:text-cyan"
                  >
                    Investigation console
                  </Link>

                  <a
                    href={repositoryUrl}
                    target="_blank"
                    rel="noreferrer"
                    className="transition hover:text-cyan"
                  >
                    Project repository
                  </a>
                </div>
              </div>
            </div>
          </div>

          <div className="mt-10 flex flex-col gap-3 border-t border-white/10 pt-6 text-xs text-slate-600 sm:flex-row sm:items-center sm:justify-between">
            <p>
              © 2026 DFIR Investigation Assistant. All rights reserved.
            </p>

            <p>
              Designed and developed by Tharun Sasanka.
            </p>
          </div>
        </div>
      </footer>
    </>
  )
}