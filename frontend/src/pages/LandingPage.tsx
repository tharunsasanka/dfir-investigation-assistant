import {
  AnimatePresence,
  motion,
} from 'framer-motion'
import type {
  LucideIcon,
} from 'lucide-react'
import {
  Activity,
  ArrowRight,
  BadgeCheck,
  BrainCircuit,
  CheckCircle2,
  ChevronUp,
  Database,
  Download,
  Eye,
  FileCheck2,
  FileJson2,
  FileText,
  Fingerprint,
  GitBranch,
  HardDrive,
  KeyRound,
  Layers3,
  LockKeyhole,
  Menu,
  Monitor,
  Network,
  Radar,
  SearchCheck,
  ServerCog,
  ShieldCheck,
  Sparkles,
  TerminalSquare,
  TimerReset,
  UsersRound,
  X,
} from 'lucide-react'
import {
  useEffect,
  useState,
} from 'react'
import {
  Link,
} from 'react-router-dom'

import {
  LandingContactFooter,
} from '../components/landing/LandingContactFooter'

type FeatureItem = {
  title: string
  description: string
  icon: LucideIcon
}

type WorkflowItem = FeatureItem & {
  number: string
}

const navigationItems = [
  {
    label: 'Workflow',
    href: '#workflow',
  },
  {
    label: 'Capabilities',
    href: '#capabilities',
  },
  {
    label: 'Evidence',
    href: '#evidence',
  },
  {
    label: 'AI Trust',
    href: '#trust',
  },
  {
    label: 'Security',
    href: '#security',
  },
  {
    label: 'Interface',
    href: '#interface',
  },
  {
    label: 'Contact',
    href: '#contact',
  },
]

const workflowItems: WorkflowItem[] = [
  {
    number: '01',
    title: 'Create the case',
    description:
      'Open a structured investigation, assign severity and preserve case context from the beginning.',
    icon: FileCheck2,
  },
  {
    number: '02',
    title: 'Collect evidence',
    description:
      'Upload forensic artefacts with integrity verification, metadata capture and chain-of-custody records.',
    icon: HardDrive,
  },
  {
    number: '03',
    title: 'Analyse activity',
    description:
      'Parse logs, detect suspicious behaviour and correlate activity across multiple evidence sources.',
    icon: SearchCheck,
  },
  {
    number: '04',
    title: 'Reconstruct events',
    description:
      'Build a unified forensic timeline that connects evidence, findings and investigation events.',
    icon: GitBranch,
  },
  {
    number: '05',
    title: 'Review conclusions',
    description:
      'Validate AI-assisted claims against traceable evidence before analyst approval.',
    icon: BadgeCheck,
  },
  {
    number: '06',
    title: 'Export the report',
    description:
      'Generate an evidence-linked investigation report suitable for review and documentation.',
    icon: FileText,
  },
]

const capabilityItems: FeatureItem[] = [
  {
    title: 'Evidence management',
    description:
      'Preserve uploaded evidence with cryptographic hashes, integrity checks and chain-of-custody history.',
    icon: Fingerprint,
  },
  {
    title: 'Security findings',
    description:
      'Surface suspicious activity with severity, confidence, indicators and supporting forensic context.',
    icon: Radar,
  },
  {
    title: 'Cross-evidence correlation',
    description:
      'Connect related activity across logs, evidence files, hosts, users, IP addresses and timestamps.',
    icon: Network,
  },
  {
    title: 'Forensic timeline',
    description:
      'Reconstruct investigation activity in a unified chronological view for faster incident understanding.',
    icon: Activity,
  },
  {
    title: 'MITRE ATT&CK context',
    description:
      'Associate detected behaviour with recognised attacker tactics and techniques.',
    icon: Layers3,
  },
  {
    title: 'Investigation reports',
    description:
      'Produce structured reports with evidence references, findings, summaries and analyst conclusions.',
    icon: FileCheck2,
  },
]

const evidenceItems: FeatureItem[] = [
  {
    title: 'Windows event data',
    description:
      'Normalised Windows security and system event records.',
    icon: ServerCog,
  },
  {
    title: 'Linux authentication logs',
    description:
      'Authentication, SSH, sudo, session and account activity.',
    icon: TerminalSquare,
  },
  {
    title: 'Structured JSON logs',
    description:
      'Machine-readable records from security and operational systems.',
    icon: FileJson2,
  },
  {
    title: 'Digital evidence files',
    description:
      'Uploaded artefacts preserved with metadata and integrity records.',
    icon: HardDrive,
  },
  {
    title: 'Network indicators',
    description:
      'IP addresses, hosts, ports and communication relationships.',
    icon: Network,
  },
  {
    title: 'Investigation metadata',
    description:
      'Case events, analyst actions, findings and audit records.',
    icon: Database,
  },
]

const trustItems: FeatureItem[] = [
  {
    title: 'Evidence-grounded claims',
    description:
      'Generated conclusions are linked to supporting evidence and investigation records.',
    icon: FileCheck2,
  },
  {
    title: 'Confidence awareness',
    description:
      'Summaries communicate uncertainty rather than presenting every result as confirmed fact.',
    icon: Radar,
  },
  {
    title: 'Hallucination guardrails',
    description:
      'Validation controls check generated claims before they are accepted into the investigation.',
    icon: ShieldCheck,
  },
  {
    title: 'Analyst review',
    description:
      'Human investigators remain responsible for reviewing, revising and approving conclusions.',
    icon: UsersRound,
  },
]

const securityItems: FeatureItem[] = [
  {
    title: 'Role-based access control',
    description:
      'Permissions restrict cases, evidence, findings, reports and administration operations.',
    icon: KeyRound,
  },
  {
    title: 'Administrator-controlled accounts',
    description:
      'Analyst accounts are created and managed by authorised administrators rather than public registration.',
    icon: UsersRound,
  },
  {
    title: 'Secure password handling',
    description:
      'Strong password validation and modern password hashing protect platform credentials.',
    icon: LockKeyhole,
  },
  {
    title: 'Audit visibility',
    description:
      'Important investigation and case-management actions remain available for accountability.',
    icon: SearchCheck,
  },
]

function SectionHeading({
  eyebrow,
  title,
  description,
}: {
  eyebrow: string
  title: string
  description: string
}) {
  return (
    <div className="mx-auto max-w-3xl text-center">
      <p className="text-sm font-medium uppercase tracking-[0.24em] text-cyan">
        {eyebrow}
      </p>

      <h2 className="mt-4 text-3xl font-bold tracking-tight text-white sm:text-4xl">
        {title}
      </h2>

      <p className="mt-5 text-base leading-7 text-slate-400 sm:text-lg">
        {description}
      </p>
    </div>
  )
}

export function LandingPage() {
  const [
    isMenuOpen,
    setIsMenuOpen,
  ] = useState(false)

  const [
    showBackToTop,
    setShowBackToTop,
  ] = useState(false)

  useEffect(() => {
    function handleScroll(): void {
      setShowBackToTop(
        window.scrollY > 640,
      )
    }

    window.addEventListener(
      'scroll',
      handleScroll,
      {
        passive: true,
      },
    )

    handleScroll()

    return () => {
      window.removeEventListener(
        'scroll',
        handleScroll,
      )
    }
  }, [])

  useEffect(() => {
    function handleEscape(
      event: KeyboardEvent,
    ): void {
      if (
        event.key === 'Escape'
      ) {
        setIsMenuOpen(false)
      }
    }

    window.addEventListener(
      'keydown',
      handleEscape,
    )

    return () => {
      window.removeEventListener(
        'keydown',
        handleEscape,
      )
    }
  }, [])

  function closeMobileMenu(): void {
    setIsMenuOpen(false)
  }

  function scrollToTop(): void {
    window.scrollTo({
      top: 0,
      behavior: 'smooth',
    })
  }

  return (
    <main className="min-h-screen overflow-hidden">
      <header className="sticky top-0 z-50 border-b border-white/10 bg-[#07111f]/90 backdrop-blur-xl">
        <div className="mx-auto flex max-w-7xl items-center justify-between gap-5 px-6 py-4">
          <Link
            to="/"
            className="flex min-w-0 items-center gap-3"
            onClick={closeMobileMenu}
          >
            <div className="shrink-0 rounded-2xl border border-cyan/20 bg-cyan/10 p-2.5 text-cyan">
              <ShieldCheck size={24} />
            </div>

            <div className="min-w-0">
              <p className="truncate font-semibold text-white">
                DFIR Assistant
              </p>

              <p className="hidden truncate text-xs text-slate-500 sm:block">
                Evidence-Grounded Investigation
              </p>
            </div>
          </Link>

          <nav className="hidden items-center gap-6 text-sm text-slate-400 xl:flex">
            {navigationItems.map(
              (item) => (
                <a
                  key={item.href}
                  href={item.href}
                  className="transition hover:text-cyan"
                >
                  {item.label}
                </a>
              ),
            )}
          </nav>

          <div className="flex items-center gap-2">
            <Link
              to="/login"
              className="hidden rounded-xl border border-white/10 px-4 py-2.5 text-sm font-medium text-slate-300 transition hover:border-cyan/40 hover:text-cyan sm:inline-flex"
            >
              Sign in
            </Link>

            <Link
              to="/dashboard"
              className="hidden items-center gap-2 rounded-xl bg-cyan px-4 py-2.5 text-sm font-semibold text-slate-950 transition hover:brightness-110 md:inline-flex"
            >
              Open Console
              <ArrowRight size={16} />
            </Link>

            <button
              type="button"
              onClick={() => {
                setIsMenuOpen(
                  (currentValue) =>
                    !currentValue,
                )
              }}
              className="rounded-xl border border-white/10 p-2.5 text-slate-300 transition hover:border-cyan/40 hover:text-cyan xl:hidden"
              aria-label="Toggle navigation menu"
              aria-expanded={isMenuOpen}
            >
              {isMenuOpen ? (
                <X size={21} />
              ) : (
                <Menu size={21} />
              )}
            </button>
          </div>
        </div>

        <AnimatePresence>
          {isMenuOpen && (
            <motion.div
              initial={{
                opacity: 0,
                height: 0,
              }}
              animate={{
                opacity: 1,
                height: 'auto',
              }}
              exit={{
                opacity: 0,
                height: 0,
              }}
              className="overflow-hidden border-t border-white/10 xl:hidden"
            >
              <nav className="mx-auto grid max-w-7xl gap-2 px-6 py-5">
                {navigationItems.map(
                  (item) => (
                    <a
                      key={item.href}
                      href={item.href}
                      onClick={closeMobileMenu}
                      className="rounded-xl px-4 py-3 text-sm text-slate-300 transition hover:bg-white/5 hover:text-cyan"
                    >
                      {item.label}
                    </a>
                  ),
                )}

                <div className="mt-3 grid gap-3 border-t border-white/10 pt-5 sm:grid-cols-2">
                  <Link
                    to="/login"
                    onClick={closeMobileMenu}
                    className="rounded-xl border border-white/10 px-4 py-3 text-center text-sm font-medium text-slate-200 transition hover:border-cyan/40 hover:text-cyan"
                  >
                    Analyst Sign In
                  </Link>

                  <Link
                    to="/dashboard"
                    onClick={closeMobileMenu}
                    className="flex items-center justify-center gap-2 rounded-xl bg-cyan px-4 py-3 text-sm font-semibold text-slate-950"
                  >
                    Open Console
                    <ArrowRight size={16} />
                  </Link>
                </div>
              </nav>
            </motion.div>
          )}
        </AnimatePresence>
      </header>

      <section className="relative">
        <div className="absolute left-[8%] top-20 h-72 w-72 rounded-full bg-cyan/10 blur-[120px]" />
        <div className="absolute right-[5%] top-10 h-96 w-96 rounded-full bg-blue-500/10 blur-[140px]" />

        <div className="relative mx-auto grid min-h-[760px] max-w-7xl items-center gap-14 px-6 py-20 lg:grid-cols-[1.02fr_0.98fr]">
          <motion.div
            initial={{
              opacity: 0,
              y: 24,
            }}
            animate={{
              opacity: 1,
              y: 0,
            }}
            transition={{
              duration: 0.7,
            }}
          >
            <div className="inline-flex items-center gap-2 rounded-full border border-cyan/25 bg-cyan/10 px-4 py-2 text-sm text-cyan">
              <Sparkles size={16} />
              Evidence-grounded digital forensics
            </div>

            <h1 className="mt-7 max-w-3xl text-4xl font-bold tracking-tight text-white sm:text-6xl sm:leading-[1.08]">
              Investigate incidents with traceable, confidence-aware AI.
            </h1>

            <p className="mt-7 max-w-2xl text-lg leading-8 text-slate-300">
              Correlate evidence, reconstruct attack timelines,
              detect suspicious activity and generate defensible
              forensic conclusions from a unified investigation
              workspace.
            </p>

            <div className="mt-9 flex flex-wrap gap-3">
              <Link
                to="/dashboard"
                className="inline-flex items-center gap-2 rounded-xl bg-cyan px-5 py-3 font-semibold text-slate-950 transition hover:-translate-y-0.5 hover:brightness-110"
              >
                Launch Investigation Console
                <ArrowRight size={18} />
              </Link>

              <a
                href="#workflow"
                className="inline-flex items-center gap-2 rounded-xl border border-white/15 px-5 py-3 font-semibold text-slate-200 transition hover:border-cyan/40 hover:text-cyan"
              >
                Explore the workflow
              </a>
            </div>

            <div className="mt-10 grid max-w-2xl gap-4 sm:grid-cols-3">
              <div className="rounded-2xl border border-white/10 bg-white/[0.03] p-4">
                <p className="text-2xl font-bold text-white">
                  SHA-256
                </p>

                <p className="mt-1 text-sm text-slate-500">
                  Evidence integrity
                </p>
              </div>

              <div className="rounded-2xl border border-white/10 bg-white/[0.03] p-4">
                <p className="text-2xl font-bold text-white">
                  RBAC
                </p>

                <p className="mt-1 text-sm text-slate-500">
                  Controlled access
                </p>
              </div>

              <div className="rounded-2xl border border-white/10 bg-white/[0.03] p-4">
                <p className="text-2xl font-bold text-white">
                  AI + Analyst
                </p>

                <p className="mt-1 text-sm text-slate-500">
                  Human-reviewed output
                </p>
              </div>
            </div>
          </motion.div>

          <motion.div
            initial={{
              opacity: 0,
              scale: 0.96,
              y: 20,
            }}
            animate={{
              opacity: 1,
              scale: 1,
              y: 0,
            }}
            transition={{
              duration: 0.8,
              delay: 0.15,
            }}
            className="relative"
          >
            <div className="absolute -inset-8 rounded-[2.5rem] bg-cyan/5 blur-3xl" />

            <div className="glass relative overflow-hidden rounded-3xl p-5 sm:p-7">
              <div className="flex items-center justify-between gap-4 border-b border-white/10 pb-5">
                <div className="flex items-center gap-3">
                  <div className="rounded-xl bg-cyan/10 p-2.5 text-cyan">
                    <Activity size={20} />
                  </div>

                  <div>
                    <p className="font-semibold text-white">
                      Investigation Workspace
                    </p>

                    <p className="text-xs text-slate-500">
                      Representative interface preview
                    </p>
                  </div>
                </div>

                <span className="rounded-full border border-red-400/20 bg-red-400/10 px-3 py-1 text-xs font-medium text-red-300">
                  Critical
                </span>
              </div>

              <div className="mt-5 grid gap-4 sm:grid-cols-3">
                <div className="rounded-2xl border border-white/10 bg-white/[0.03] p-4">
                  <p className="text-xs uppercase tracking-wider text-slate-600">
                    Evidence
                  </p>

                  <p className="mt-2 text-2xl font-semibold text-white">
                    12
                  </p>

                  <p className="mt-1 text-xs text-emerald-300">
                    Integrity verified
                  </p>
                </div>

                <div className="rounded-2xl border border-white/10 bg-white/[0.03] p-4">
                  <p className="text-xs uppercase tracking-wider text-slate-600">
                    Findings
                  </p>

                  <p className="mt-2 text-2xl font-semibold text-white">
                    8
                  </p>

                  <p className="mt-1 text-xs text-amber-300">
                    3 need review
                  </p>
                </div>

                <div className="rounded-2xl border border-white/10 bg-white/[0.03] p-4">
                  <p className="text-xs uppercase tracking-wider text-slate-600">
                    Confidence
                  </p>

                  <p className="mt-2 text-2xl font-semibold text-white">
                    92%
                  </p>

                  <p className="mt-1 text-xs text-cyan">
                    Evidence linked
                  </p>
                </div>
              </div>

              <div className="mt-5 rounded-2xl border border-white/10 bg-[#091524]/80 p-5">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <p className="font-medium text-white">
                      Unified forensic timeline
                    </p>

                    <p className="mt-1 text-xs text-slate-500">
                      Correlated investigation activity
                    </p>
                  </div>

                  <TimerReset
                    size={19}
                    className="text-cyan"
                  />
                </div>

                <div className="mt-5 space-y-4">
                  <div className="grid grid-cols-[72px_14px_1fr] items-start gap-3">
                    <p className="text-xs text-slate-500">
                      09:14:22
                    </p>

                    <div className="mt-1.5 h-3 w-3 rounded-full border-2 border-red-300 bg-red-400/30" />

                    <div>
                      <p className="text-sm font-medium text-slate-200">
                        Suspicious authentication detected
                      </p>

                      <p className="mt-1 text-xs text-slate-500">
                        Windows security log · Host FIN-WS-04
                      </p>
                    </div>
                  </div>

                  <div className="grid grid-cols-[72px_14px_1fr] items-start gap-3">
                    <p className="text-xs text-slate-500">
                      09:16:08
                    </p>

                    <div className="mt-1.5 h-3 w-3 rounded-full border-2 border-amber-300 bg-amber-400/30" />

                    <div>
                      <p className="text-sm font-medium text-slate-200">
                        Privileged process execution
                      </p>

                      <p className="mt-1 text-xs text-slate-500">
                        Correlated with the same user and endpoint
                      </p>
                    </div>
                  </div>

                  <div className="grid grid-cols-[72px_14px_1fr] items-start gap-3">
                    <p className="text-xs text-slate-500">
                      09:18:41
                    </p>

                    <div className="mt-1.5 h-3 w-3 rounded-full border-2 border-cyan bg-cyan/30" />

                    <div>
                      <p className="text-sm font-medium text-slate-200">
                        Evidence-linked finding generated
                      </p>

                      <p className="mt-1 text-xs text-slate-500">
                        Awaiting analyst validation
                      </p>
                    </div>
                  </div>
                </div>
              </div>

              <div className="mt-5 flex items-start gap-3 rounded-2xl border border-emerald-400/15 bg-emerald-400/[0.06] p-4">
                <CheckCircle2
                  size={19}
                  className="mt-0.5 shrink-0 text-emerald-300"
                />

                <div>
                  <p className="text-sm font-medium text-emerald-200">
                    Evidence traceability active
                  </p>

                  <p className="mt-1 text-xs text-emerald-100/60">
                    Every reported claim can be reviewed against its source.
                  </p>
                </div>
              </div>
            </div>
          </motion.div>
        </div>
      </section>

      <section
        id="workflow"
        className="border-y border-white/10 bg-white/[0.015] py-24"
      >
        <div className="mx-auto max-w-7xl px-6">
          <SectionHeading
            eyebrow="Investigation workflow"
            title="From collected evidence to defensible conclusions"
            description="A structured workflow keeps evidence, findings, timelines, analyst decisions and exported reports connected throughout the investigation."
          />

          <div className="mt-14 grid gap-5 md:grid-cols-2 xl:grid-cols-3">
            {workflowItems.map(
              (item, index) => {
                const Icon = item.icon

                return (
                  <motion.article
                    key={item.number}
                    initial={{
                      opacity: 0,
                      y: 24,
                    }}
                    whileInView={{
                      opacity: 1,
                      y: 0,
                    }}
                    viewport={{
                      once: true,
                      amount: 0.25,
                    }}
                    transition={{
                      duration: 0.5,
                      delay: index * 0.06,
                    }}
                    className="glass group rounded-2xl p-6 transition duration-300 hover:-translate-y-1 hover:border-cyan/30"
                  >
                    <div className="flex items-start justify-between gap-4">
                      <div className="rounded-xl bg-cyan/10 p-3 text-cyan">
                        <Icon size={21} />
                      </div>

                      <span className="text-sm font-semibold text-slate-600">
                        {item.number}
                      </span>
                    </div>

                    <h3 className="mt-6 text-lg font-semibold text-white">
                      {item.title}
                    </h3>

                    <p className="mt-3 text-sm leading-6 text-slate-400">
                      {item.description}
                    </p>
                  </motion.article>
                )
              },
            )}
          </div>
        </div>
      </section>

      <section
        id="capabilities"
        className="py-24"
      >
        <div className="mx-auto max-w-7xl px-6">
          <SectionHeading
            eyebrow="Core capabilities"
            title="One workspace for the full forensic investigation"
            description="The platform combines evidence handling, automated analysis, correlation, timeline reconstruction and reporting without separating the investigation into disconnected tools."
          />

          <div className="mt-14 grid gap-5 md:grid-cols-2 xl:grid-cols-3">
            {capabilityItems.map(
              (item, index) => {
                const Icon = item.icon

                return (
                  <motion.article
                    key={item.title}
                    initial={{
                      opacity: 0,
                      y: 24,
                    }}
                    whileInView={{
                      opacity: 1,
                      y: 0,
                    }}
                    viewport={{
                      once: true,
                      amount: 0.25,
                    }}
                    transition={{
                      duration: 0.5,
                      delay: index * 0.06,
                    }}
                    className="rounded-2xl border border-white/10 bg-white/[0.025] p-6 transition hover:-translate-y-1 hover:border-cyan/30 hover:bg-white/[0.04]"
                  >
                    <div className="inline-flex rounded-xl bg-cyan/10 p-3 text-cyan">
                      <Icon size={22} />
                    </div>

                    <h3 className="mt-6 text-lg font-semibold text-white">
                      {item.title}
                    </h3>

                    <p className="mt-3 text-sm leading-6 text-slate-400">
                      {item.description}
                    </p>
                  </motion.article>
                )
              },
            )}
          </div>
        </div>
      </section>

      <section
        id="evidence"
        className="border-y border-white/10 bg-white/[0.015] py-24"
      >
        <div className="mx-auto grid max-w-7xl gap-14 px-6 lg:grid-cols-[0.85fr_1.15fr] lg:items-center">
          <motion.div
            initial={{
              opacity: 0,
              x: -24,
            }}
            whileInView={{
              opacity: 1,
              x: 0,
            }}
            viewport={{
              once: true,
              amount: 0.3,
            }}
          >
            <p className="text-sm font-medium uppercase tracking-[0.24em] text-cyan">
              Evidence sources
            </p>

            <h2 className="mt-4 text-3xl font-bold tracking-tight text-white sm:text-4xl">
              Built to connect different forensic records
            </h2>

            <p className="mt-5 text-base leading-7 text-slate-400 sm:text-lg">
              Investigations rarely depend on one log source. The
              platform normalises and connects records so analysts
              can examine related behaviour across systems.
            </p>

            <div className="mt-8 rounded-2xl border border-cyan/15 bg-cyan/[0.06] p-5">
              <div className="flex items-start gap-3">
                <Database
                  size={21}
                  className="mt-0.5 shrink-0 text-cyan"
                />

                <div>
                  <p className="font-medium text-white">
                    Preserved investigation context
                  </p>

                  <p className="mt-2 text-sm leading-6 text-slate-400">
                    Evidence metadata, parsed events, findings,
                    correlations and analyst activity remain linked
                    to the correct case.
                  </p>
                </div>
              </div>
            </div>
          </motion.div>

          <div className="grid gap-4 sm:grid-cols-2">
            {evidenceItems.map(
              (item, index) => {
                const Icon = item.icon

                return (
                  <motion.article
                    key={item.title}
                    initial={{
                      opacity: 0,
                      y: 20,
                    }}
                    whileInView={{
                      opacity: 1,
                      y: 0,
                    }}
                    viewport={{
                      once: true,
                      amount: 0.2,
                    }}
                    transition={{
                      duration: 0.45,
                      delay: index * 0.05,
                    }}
                    className="glass rounded-2xl p-5"
                  >
                    <div className="flex items-start gap-4">
                      <div className="rounded-xl bg-white/5 p-3 text-cyan">
                        <Icon size={20} />
                      </div>

                      <div>
                        <h3 className="font-semibold text-white">
                          {item.title}
                        </h3>

                        <p className="mt-2 text-sm leading-6 text-slate-400">
                          {item.description}
                        </p>
                      </div>
                    </div>
                  </motion.article>
                )
              },
            )}
          </div>
        </div>
      </section>

      <section
        id="trust"
        className="py-24"
      >
        <div className="mx-auto max-w-7xl px-6">
          <div className="grid gap-14 lg:grid-cols-2 lg:items-center">
            <motion.div
              initial={{
                opacity: 0,
                y: 24,
              }}
              whileInView={{
                opacity: 1,
                y: 0,
              }}
              viewport={{
                once: true,
                amount: 0.3,
              }}
              className="glass relative overflow-hidden rounded-3xl p-7 sm:p-9"
            >
              <div className="absolute right-0 top-0 h-56 w-56 rounded-full bg-violet-500/10 blur-[100px]" />

              <div className="relative">
                <div className="inline-flex rounded-2xl bg-violet-400/10 p-3 text-violet-300">
                  <BrainCircuit size={26} />
                </div>

                <h3 className="mt-6 text-2xl font-semibold text-white">
                  AI assistance without hiding the evidence
                </h3>

                <p className="mt-4 leading-7 text-slate-400">
                  AI-generated investigation summaries are treated
                  as reviewable assistance rather than unquestioned
                  conclusions.
                </p>

                <div className="mt-7 space-y-4">
                  <div className="rounded-2xl border border-white/10 bg-white/[0.03] p-5">
                    <p className="text-xs uppercase tracking-wider text-slate-600">
                      Generated claim
                    </p>

                    <p className="mt-2 text-sm leading-6 text-slate-200">
                      Multiple failed sign-ins were followed by a
                      successful privileged session from the same source.
                    </p>
                  </div>

                  <div className="grid gap-4 sm:grid-cols-2">
                    <div className="rounded-2xl border border-emerald-400/15 bg-emerald-400/[0.06] p-4">
                      <p className="text-xs uppercase tracking-wider text-emerald-300/70">
                        Confidence
                      </p>

                      <p className="mt-2 text-2xl font-semibold text-emerald-200">
                        High
                      </p>
                    </div>

                    <div className="rounded-2xl border border-cyan/15 bg-cyan/[0.06] p-4">
                      <p className="text-xs uppercase tracking-wider text-cyan/70">
                        Evidence links
                      </p>

                      <p className="mt-2 text-2xl font-semibold text-cyan">
                        4
                      </p>
                    </div>
                  </div>

                  <div className="flex items-start gap-3 rounded-2xl border border-amber-400/15 bg-amber-400/[0.06] p-4">
                    <UsersRound
                      size={19}
                      className="mt-0.5 shrink-0 text-amber-300"
                    />

                    <p className="text-sm leading-6 text-amber-100/75">
                      Final approval remains with the assigned analyst
                      or investigation reviewer.
                    </p>
                  </div>
                </div>
              </div>
            </motion.div>

            <div>
              <p className="text-sm font-medium uppercase tracking-[0.24em] text-cyan">
                AI trust and traceability
              </p>

              <h2 className="mt-4 text-3xl font-bold tracking-tight text-white sm:text-4xl">
                Transparent assistance for serious investigations
              </h2>

              <p className="mt-5 text-base leading-7 text-slate-400 sm:text-lg">
                Every generated conclusion should be understandable,
                reviewable and connected to the evidence that supports it.
              </p>

              <div className="mt-8 grid gap-4">
                {trustItems.map(
                  (item) => {
                    const Icon = item.icon

                    return (
                      <div
                        key={item.title}
                        className="flex items-start gap-4 rounded-2xl border border-white/10 bg-white/[0.025] p-5"
                      >
                        <div className="rounded-xl bg-cyan/10 p-3 text-cyan">
                          <Icon size={20} />
                        </div>

                        <div>
                          <h3 className="font-semibold text-white">
                            {item.title}
                          </h3>

                          <p className="mt-2 text-sm leading-6 text-slate-400">
                            {item.description}
                          </p>
                        </div>
                      </div>
                    )
                  },
                )}
              </div>
            </div>
          </div>
        </div>
      </section>

      <section
        id="security"
        className="border-y border-white/10 bg-white/[0.015] py-24"
      >
        <div className="mx-auto max-w-7xl px-6">
          <SectionHeading
            eyebrow="Security and access"
            title="Designed for controlled forensic environments"
            description="Sensitive evidence and investigation data require stronger controls than an ordinary public web application."
          />

          <div className="mt-14 grid gap-5 md:grid-cols-2">
            {securityItems.map(
              (item, index) => {
                const Icon = item.icon

                return (
                  <motion.article
                    key={item.title}
                    initial={{
                      opacity: 0,
                      y: 20,
                    }}
                    whileInView={{
                      opacity: 1,
                      y: 0,
                    }}
                    viewport={{
                      once: true,
                      amount: 0.25,
                    }}
                    transition={{
                      duration: 0.45,
                      delay: index * 0.06,
                    }}
                    className="glass rounded-2xl p-6"
                  >
                    <div className="flex items-start gap-4">
                      <div className="rounded-xl bg-cyan/10 p-3 text-cyan">
                        <Icon size={22} />
                      </div>

                      <div>
                        <h3 className="text-lg font-semibold text-white">
                          {item.title}
                        </h3>

                        <p className="mt-3 text-sm leading-6 text-slate-400">
                          {item.description}
                        </p>
                      </div>
                    </div>
                  </motion.article>
                )
              },
            )}
          </div>
        </div>
      </section>

      <section
        id="interface"
        className="py-24"
      >
        <div className="mx-auto max-w-7xl px-6">
          <SectionHeading
            eyebrow="Platform interface"
            title="A focused workspace for forensic analysts"
            description="Cases, evidence, findings, correlation, timelines, AI summaries and reports remain accessible from one protected investigation environment."
          />

          <motion.div
            initial={{
              opacity: 0,
              y: 28,
            }}
            whileInView={{
              opacity: 1,
              y: 0,
            }}
            viewport={{
              once: true,
              amount: 0.2,
            }}
            className="glass mt-14 overflow-hidden rounded-3xl"
          >
            <div className="flex items-center justify-between gap-4 border-b border-white/10 px-5 py-4">
              <div className="flex items-center gap-3">
                <div className="flex gap-1.5">
                  <span className="h-2.5 w-2.5 rounded-full bg-red-400/70" />
                  <span className="h-2.5 w-2.5 rounded-full bg-amber-400/70" />
                  <span className="h-2.5 w-2.5 rounded-full bg-emerald-400/70" />
                </div>

                <p className="text-xs text-slate-500">
                  Protected Investigation Console
                </p>
              </div>

              <Monitor
                size={18}
                className="text-cyan"
              />
            </div>

            <div className="grid lg:grid-cols-[220px_1fr]">
              <aside className="border-b border-white/10 bg-white/[0.02] p-5 lg:border-b-0 lg:border-r">
                <div className="flex items-center gap-3">
                  <div className="rounded-xl bg-cyan/10 p-2 text-cyan">
                    <ShieldCheck size={18} />
                  </div>

                  <div>
                    <p className="text-sm font-semibold text-white">
                      DFIR Assistant
                    </p>

                    <p className="text-xs text-slate-600">
                      Analyst console
                    </p>
                  </div>
                </div>

                <div className="mt-7 grid grid-cols-2 gap-2 lg:grid-cols-1">
                  {[
                    'Dashboard',
                    'Cases',
                    'Investigation',
                    'Settings',
                  ].map(
                    (item, index) => (
                      <div
                        key={item}
                        className={[
                          'rounded-xl px-3 py-2.5 text-xs',
                          index === 2
                            ? 'bg-cyan/10 text-cyan'
                            : 'text-slate-500',
                        ].join(' ')}
                      >
                        {item}
                      </div>
                    ),
                  )}
                </div>
              </aside>

              <div className="p-5 sm:p-7">
                <div className="flex flex-wrap items-start justify-between gap-4">
                  <div>
                    <p className="text-sm text-cyan">
                      Active investigation
                    </p>

                    <h3 className="mt-1 text-xl font-semibold text-white">
                      Suspicious Account Activity
                    </h3>

                    <p className="mt-2 text-sm text-slate-500">
                      Representative interface preview using sample display data
                    </p>
                  </div>

                  <span className="rounded-full border border-red-400/20 bg-red-400/10 px-3 py-1 text-xs text-red-300">
                    Critical severity
                  </span>
                </div>

                <div className="mt-7 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
                  {[
                    {
                      label: 'Evidence',
                      value: '12',
                    },
                    {
                      label: 'Findings',
                      value: '8',
                    },
                    {
                      label: 'Correlations',
                      value: '5',
                    },
                    {
                      label: 'Timeline events',
                      value: '34',
                    },
                  ].map(
                    (metric) => (
                      <div
                        key={metric.label}
                        className="rounded-2xl border border-white/10 bg-white/[0.025] p-4"
                      >
                        <p className="text-xs uppercase tracking-wider text-slate-600">
                          {metric.label}
                        </p>

                        <p className="mt-2 text-2xl font-semibold text-white">
                          {metric.value}
                        </p>
                      </div>
                    ),
                  )}
                </div>

                <div className="mt-5 grid gap-5 xl:grid-cols-[1.2fr_0.8fr]">
                  <div className="rounded-2xl border border-white/10 bg-white/[0.02] p-5">
                    <div className="flex items-center justify-between gap-4">
                      <div>
                        <p className="font-medium text-white">
                          Recent investigation events
                        </p>

                        <p className="mt-1 text-xs text-slate-500">
                          Chronological evidence and findings
                        </p>
                      </div>

                      <Activity
                        size={19}
                        className="text-cyan"
                      />
                    </div>

                    <div className="mt-5 space-y-3">
                      {[
                        'Failed authentication sequence detected',
                        'Successful privileged session identified',
                        'Related network indicator correlated',
                        'AI-assisted summary generated',
                      ].map(
                        (event, index) => (
                          <div
                            key={event}
                            className="flex items-start gap-3 rounded-xl border border-white/5 bg-white/[0.02] p-3"
                          >
                            <span
                              className={[
                                'mt-1.5 h-2.5 w-2.5 shrink-0 rounded-full',
                                index === 0
                                  ? 'bg-red-400'
                                  : index === 1
                                    ? 'bg-amber-400'
                                    : 'bg-cyan',
                              ].join(' ')}
                            />

                            <div>
                              <p className="text-sm text-slate-300">
                                {event}
                              </p>

                              <p className="mt-1 text-xs text-slate-600">
                                Evidence linked and reviewable
                              </p>
                            </div>
                          </div>
                        ),
                      )}
                    </div>
                  </div>

                  <div className="rounded-2xl border border-white/10 bg-white/[0.02] p-5">
                    <p className="font-medium text-white">
                      Investigation actions
                    </p>

                    <div className="mt-5 grid gap-3">
                      <div className="flex items-center gap-3 rounded-xl border border-cyan/15 bg-cyan/[0.05] p-4">
                        <Eye
                          size={18}
                          className="text-cyan"
                        />

                        <span className="text-sm text-slate-300">
                          Review linked evidence
                        </span>
                      </div>

                      <div className="flex items-center gap-3 rounded-xl border border-white/10 bg-white/[0.03] p-4">
                        <BrainCircuit
                          size={18}
                          className="text-violet-300"
                        />

                        <span className="text-sm text-slate-300">
                          Validate AI summary
                        </span>
                      </div>

                      <div className="flex items-center gap-3 rounded-xl border border-white/10 bg-white/[0.03] p-4">
                        <Download
                          size={18}
                          className="text-emerald-300"
                        />

                        <span className="text-sm text-slate-300">
                          Export investigation report
                        </span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </motion.div>
        </div>
      </section>

      <section className="border-y border-white/10 bg-white/[0.015] py-24">
        <div className="mx-auto max-w-7xl px-6">
          <motion.div
            initial={{
              opacity: 0,
              y: 24,
            }}
            whileInView={{
              opacity: 1,
              y: 0,
            }}
            viewport={{
              once: true,
              amount: 0.3,
            }}
            className="glass relative overflow-hidden rounded-3xl px-6 py-14 text-center sm:px-12"
          >
            <div className="absolute left-1/2 top-0 h-72 w-72 -translate-x-1/2 rounded-full bg-cyan/10 blur-[120px]" />

            <div className="relative mx-auto max-w-3xl">
              <div className="mx-auto inline-flex rounded-2xl bg-cyan/10 p-3 text-cyan">
                <ShieldCheck size={28} />
              </div>

              <h2 className="mt-6 text-3xl font-bold tracking-tight text-white sm:text-4xl">
                Begin a structured digital forensic investigation
              </h2>

              <p className="mt-5 text-base leading-7 text-slate-400 sm:text-lg">
                Use a unified workspace to preserve evidence,
                identify suspicious activity, validate conclusions
                and produce evidence-linked reports.
              </p>

              <div className="mt-8 flex flex-wrap justify-center gap-3">
                <Link
                  to="/dashboard"
                  className="inline-flex items-center gap-2 rounded-xl bg-cyan px-5 py-3 font-semibold text-slate-950 transition hover:-translate-y-0.5 hover:brightness-110"
                >
                  Open Investigation Console
                  <ArrowRight size={18} />
                </Link>

                <Link
                  to="/login"
                  className="inline-flex items-center gap-2 rounded-xl border border-white/15 px-5 py-3 font-semibold text-slate-200 transition hover:border-cyan/40 hover:text-cyan"
                >
                  Sign in securely
                </Link>
              </div>
            </div>
          </motion.div>
        </div>
      </section>

      <LandingContactFooter />

      <AnimatePresence>
        {showBackToTop && (
          <motion.button
            type="button"
            initial={{
              opacity: 0,
              scale: 0.85,
              y: 12,
            }}
            animate={{
              opacity: 1,
              scale: 1,
              y: 0,
            }}
            exit={{
              opacity: 0,
              scale: 0.85,
              y: 12,
            }}
            onClick={scrollToTop}
            className="fixed bottom-6 right-6 z-40 rounded-2xl border border-cyan/25 bg-[#0b1a2b]/90 p-3 text-cyan shadow-2xl backdrop-blur-xl transition hover:-translate-y-1 hover:bg-cyan hover:text-slate-950"
            aria-label="Back to top"
          >
            <ChevronUp size={22} />
          </motion.button>
        )}
      </AnimatePresence>
    </main>
  )
}