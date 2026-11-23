"""SCR-4: human completion notice, separate from JSON reports and exit gates."""

def completion_message(exposure, workload_passed, cleanup_confirmed, configuration=None, exit_code=5, execution_ok=True):
    score = exposure if isinstance(exposure, dict) else {}
    n, total = score.get('score'), score.get('of')
    valid = (score.get('valid') is True and type(n) is int and type(total) is int
             and 1 <= total <= 6 and 0 <= n <= total)
    coverage = score.get('coverage')
    covered = isinstance(coverage, dict) and coverage.get('complete') is True
    config = configuration if isinstance(configuration, dict) else {}
    requirements = config.get('benchmark_requirements_met') is True
    clean, worked = cleanup_confirmed is True, workload_passed is True
    if not clean:
        state = 'incomplete: cleanup unconfirmed'
    elif not valid:
        state = 'incomplete: RC assessment unavailable'
    elif not worked:
        state = 'collected; workload not verified'
    elif execution_ok is not True:
        state = 'incomplete: execution interrupted'
    elif not covered or not requirements:
        state = 'completed with gaps'
    else:
        state = 'completed'
    ranking = '%d/%d' % (n, total) if valid else 'unavailable'
    code = str(exit_code) if type(exit_code) is int and exit_code in (0, 2, 5, 6) else 'unavailable'
    notice = ('Managed assessment %s | RC exposure %s | workload %s | cleanup %s | exit %s'
              % (state, ranking, 'verified' if worked else 'not verified', 'confirmed' if clean else 'unconfirmed', code))
    if exit_code == 5 and state == 'completed with gaps':
        notice += ': requirements remain unmet; the RC assessment completed'
    elif exit_code == 6:
        notice += ': findings reported'
    return notice + '.'
