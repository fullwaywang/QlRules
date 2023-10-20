/**
 * @name openssl-8aed2a7548362e88e84a7feb795a3a97e8395008-EC_GROUP_free
 * @id cpp/openssl/8aed2a7548362e88e84a7feb795a3a97e8395008/EC-GROUP-free
 * @description openssl-8aed2a7548362e88e84a7feb795a3a97e8395008-EC_GROUP_free CVE-2016-7056
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vgroup_123, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(PointerFieldAccess).getTarget().getName()="mont_data"
		and target_0.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgroup_123
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("BN_MONT_CTX_free")
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="mont_data"
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgroup_123
		and (func.getEntryPoint().(BlockStmt).getStmt(3)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(3).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vgroup_123) {
	exists(AddressOfExpr target_1 |
		target_1.getOperand().(PointerFieldAccess).getTarget().getName()="extra_data"
		and target_1.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgroup_123
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("EC_EX_DATA_free_all_data"))
}

from Function func, Parameter vgroup_123
where
not func_0(vgroup_123, func)
and vgroup_123.getType().hasName("EC_GROUP *")
and func_1(vgroup_123)
and vgroup_123.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
