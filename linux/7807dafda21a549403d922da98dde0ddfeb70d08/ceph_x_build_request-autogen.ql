/**
 * @name linux-7807dafda21a549403d922da98dde0ddfeb70d08-ceph_x_build_request
 * @id cpp/linux/7807dafda21a549403d922da98dde0ddfeb70d08/ceph_x_build_request
 * @description linux-7807dafda21a549403d922da98dde0ddfeb70d08-ceph_x_build_request CVE-2021-20288
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vauth_507) {
	exists(Literal target_0 |
		target_0.getValue()="2"
		and not target_0.getValue()="3"
		and target_0.getParent().(AssignExpr).getParent().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="struct_v"
		and target_0.getParent().(AssignExpr).getParent().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vauth_507)
}

from Function func, Variable vauth_507
where
func_0(vauth_507)
and vauth_507.getType().hasName("ceph_x_authenticate *")
and vauth_507.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
