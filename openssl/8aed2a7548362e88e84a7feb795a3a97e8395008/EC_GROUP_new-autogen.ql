/**
 * @name openssl-8aed2a7548362e88e84a7feb795a3a97e8395008-EC_GROUP_new
 * @id cpp/openssl/8aed2a7548362e88e84a7feb795a3a97e8395008/EC-GROUP-new
 * @description openssl-8aed2a7548362e88e84a7feb795a3a97e8395008-EC_GROUP_new NULL
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(SizeofExprOperator target_0 |
		target_0.getValue()="232"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Variable vret_78, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="mont_data"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_78
		and target_1.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(7)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(7).getFollowingStmt()=target_1))
}

predicate func_2(Variable vret_78) {
	exists(AssignExpr target_2 |
		target_2.getLValue().(PointerFieldAccess).getTarget().getName()="extra_data"
		and target_2.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_78
		and target_2.getRValue().(Literal).getValue()="0")
}

from Function func, Variable vret_78
where
func_0(func)
and not func_1(vret_78, func)
and vret_78.getType().hasName("EC_GROUP *")
and func_2(vret_78)
and vret_78.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
