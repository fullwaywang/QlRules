/**
 * @name openssl-8aed2a7548362e88e84a7feb795a3a97e8395008-EC_GROUP_clear_free
 * @id cpp/openssl/8aed2a7548362e88e84a7feb795a3a97e8395008/EC-GROUP-clear-free
 * @description openssl-8aed2a7548362e88e84a7feb795a3a97e8395008-EC_GROUP_clear_free CVE-2016-7056
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

predicate func_1(Parameter vgroup_144, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(PointerFieldAccess).getTarget().getName()="mont_data"
		and target_1.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgroup_144
		and target_1.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("BN_MONT_CTX_free")
		and target_1.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="mont_data"
		and target_1.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgroup_144
		and (func.getEntryPoint().(BlockStmt).getStmt(3)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(3).getFollowingStmt()=target_1))
}

predicate func_2(Parameter vgroup_144) {
	exists(AddressOfExpr target_2 |
		target_2.getOperand().(PointerFieldAccess).getTarget().getName()="extra_data"
		and target_2.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgroup_144
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("EC_EX_DATA_clear_free_all_data"))
}

from Function func, Parameter vgroup_144
where
func_0(func)
and not func_1(vgroup_144, func)
and vgroup_144.getType().hasName("EC_GROUP *")
and func_2(vgroup_144)
and vgroup_144.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
