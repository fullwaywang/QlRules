/**
 * @name openssl-1b0fe00e2704b5e20334a16d3c9099d1ba2ef1be-rand_drbg_new
 * @id cpp/openssl/1b0fe00e2704b5e20334a16d3c9099d1ba2ef1be/rand-drbg-new
 * @description openssl-1b0fe00e2704b5e20334a16d3c9099d1ba2ef1be-rand_drbg_new CVE-2019-1549
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vdrbg_191) {
	exists(PointerFieldAccess target_0 |
		target_0.getTarget().getName()="fork_count"
		and target_0.getQualifier().(VariableAccess).getTarget()=vdrbg_191)
}

predicate func_1(Function func) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("openssl_get_fork_id")
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Variable vdrbg_191, Variable vrand_fork_count) {
	exists(VariableAccess target_2 |
		target_2.getTarget()=vrand_fork_count
		and target_2.getParent().(AssignExpr).getRValue() = target_2
		and target_2.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="fork_count"
		and target_2.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdrbg_191)
}

from Function func, Variable vdrbg_191, Variable vrand_fork_count
where
func_0(vdrbg_191)
and not func_1(func)
and func_2(vdrbg_191, vrand_fork_count)
and vdrbg_191.getType().hasName("RAND_DRBG *")
and vdrbg_191.getParentScope+() = func
and not vrand_fork_count.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
