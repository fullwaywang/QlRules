/**
 * @name openjpeg-8f5aff1dff510a964d3901d0fba281abec98ab63-opj_pi_next_pcrl
 * @id cpp/openjpeg/8f5aff1dff510a964d3901d0fba281abec98ab63/opj-pi-next-pcrl
 * @description openjpeg-8f5aff1dff510a964d3901d0fba281abec98ab63-src/lib/openjp2/pi.c-opj_pi_next_pcrl CVE-2020-27845
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, StringLiteral target_0) {
		target_0.getValue()="opj_pi_next_pcrl(): invalid compno0/compno1"
		and not target_0.getValue()="opj_pi_next_pcrl(): invalid compno0/compno1\n"
		and target_0.getEnclosingFunction() = func
}

from Function func, StringLiteral target_0
where
func_0(func, target_0)
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
