/**
 * @name openssl-7725e7bfe6f2ce8146b6552b44e0d226be7638e7-ossl_policy_cache_set_mapping
 * @id cpp/openssl/7725e7bfe6f2ce8146b6552b44e0d226be7638e7/ossl-policy-cache-set-mapping
 * @description openssl-7725e7bfe6f2ce8146b6552b44e0d226be7638e7-ossl_policy_cache_set_mapping CVE-2022-3996
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vx_22, Variable vret_28, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vret_28
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(UnaryMinusExpr).getValue()="-1"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("CRYPTO_THREAD_write_lock")
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="lock"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vx_22
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getTarget().getName()="ex_flags"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vx_22
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignOrExpr).getRValue().(Literal).getValue()="2048"
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("CRYPTO_THREAD_unlock")
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="lock"
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vx_22
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_0)
}

from Function func, Parameter vx_22, Variable vret_28
where
func_0(vx_22, vret_28, func)
and vx_22.getType().hasName("X509 *")
and vret_28.getType().hasName("int")
and vx_22.getParentScope+() = func
and vret_28.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
