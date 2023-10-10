/**
 * @name nettle-c71d2c9d20eeebb985e3872e4550137209e3ce4d-ecc_256_modq
 * @id cpp/nettle/c71d2c9d20eeebb985e3872e4550137209e3ce4d/ecc-256-modq
 * @description nettle-c71d2c9d20eeebb985e3872e4550137209e3ce4d-ecc-256.c-ecc_256_modq CVE-2015-8803
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vu0_137, ExprStmt target_1, VariableAccess target_0) {
		target_0.getTarget()=vu0_137
		and target_1.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getLocation())
}

predicate func_1(Variable vu0_137, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vu0_137
}

from Function func, Variable vu0_137, VariableAccess target_0, ExprStmt target_1
where
func_0(vu0_137, target_1, target_0)
and func_1(vu0_137, target_1)
and vu0_137.getType().hasName("mp_limb_t")
and vu0_137.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
