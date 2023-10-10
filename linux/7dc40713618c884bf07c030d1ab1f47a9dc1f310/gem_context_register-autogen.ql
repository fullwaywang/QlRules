/**
 * @name linux-7dc40713618c884bf07c030d1ab1f47a9dc1f310-gem_context_register
 * @id cpp/linux/7dc40713618c884bf07c030d1ab1f47a9dc1f310/gem_context_register
 * @description linux-7dc40713618c884bf07c030d1ab1f47a9dc1f310-gem_context_register 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vfpriv_589, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("mutex_lock_nested")
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="context_idr_lock"
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfpriv_589
		and target_0.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(6)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(6).getFollowingStmt()=target_0))
}

predicate func_1(Variable vret_591, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vret_591
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_1.getThen() instanceof ExprStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(8)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(8).getFollowingStmt()=target_1))
}

predicate func_2(Parameter vfpriv_589, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("mutex_unlock")
		and target_2.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="context_idr_lock"
		and target_2.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfpriv_589
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_2))
}

predicate func_3(Variable vret_591, Parameter vctx_588, Function func) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="user_handle"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_588
		and target_3.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vret_591
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_3)
}

predicate func_4(Parameter vfpriv_589, Parameter vctx_588) {
	exists(AssignExpr target_4 |
		target_4.getLValue().(ValueFieldAccess).getTarget().getName()="file"
		and target_4.getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="vm"
		and target_4.getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ppgtt"
		and target_4.getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_588
		and target_4.getRValue().(VariableAccess).getTarget()=vfpriv_589)
}

predicate func_5(Parameter vfpriv_589) {
	exists(PointerFieldAccess target_5 |
		target_5.getTarget().getName()="context_idr"
		and target_5.getQualifier().(VariableAccess).getTarget()=vfpriv_589)
}

predicate func_6(Parameter vfpriv_589, Variable vret_591, Parameter vctx_588) {
	exists(AssignExpr target_6 |
		target_6.getLValue().(VariableAccess).getTarget()=vret_591
		and target_6.getRValue().(FunctionCall).getTarget().hasName("idr_alloc")
		and target_6.getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="context_idr"
		and target_6.getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfpriv_589
		and target_6.getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vctx_588
		and target_6.getRValue().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_6.getRValue().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_6.getRValue().(FunctionCall).getArgument(4).(BitwiseOrExpr).getValue()="6291648"
		and target_6.getRValue().(FunctionCall).getArgument(4).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getValue()="6291520"
		and target_6.getRValue().(FunctionCall).getArgument(4).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(Literal).getValue()="2097152"
		and target_6.getRValue().(FunctionCall).getArgument(4).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(Literal).getValue()="4194304"
		and target_6.getRValue().(FunctionCall).getArgument(4).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(Literal).getValue()="64"
		and target_6.getRValue().(FunctionCall).getArgument(4).(BitwiseOrExpr).getRightOperand().(Literal).getValue()="128")
}

from Function func, Parameter vfpriv_589, Variable vret_591, Parameter vctx_588
where
not func_0(vfpriv_589, func)
and not func_1(vret_591, func)
and not func_2(vfpriv_589, func)
and func_3(vret_591, vctx_588, func)
and vfpriv_589.getType().hasName("drm_i915_file_private *")
and func_4(vfpriv_589, vctx_588)
and func_5(vfpriv_589)
and vret_591.getType().hasName("int")
and func_6(vfpriv_589, vret_591, vctx_588)
and vctx_588.getType().hasName("i915_gem_context *")
and vfpriv_589.getParentScope+() = func
and vret_591.getParentScope+() = func
and vctx_588.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
