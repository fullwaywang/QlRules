/**
 * @name linux-2555283eb40df89945557273121e9393ef9b542b-anon_vma_fork
 * @id cpp/linux/2555283eb40df89945557273121e9393ef9b542b/anon-vma-fork
 * @description linux-2555283eb40df89945557273121e9393ef9b542b-anon_vma_fork 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vanon_vma_335) {
	exists(PostfixIncrExpr target_0 |
		target_0.getOperand().(PointerFieldAccess).getTarget().getName()="num_active_vmas"
		and target_0.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vanon_vma_335)
}

predicate func_1(Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="num_children"
		and target_1.getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier() instanceof PointerFieldAccess
		and func.getEntryPoint().(BlockStmt).getStmt(19)=target_1)
}

predicate func_2(Variable vanon_vma_335) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="parent"
		and target_2.getQualifier().(VariableAccess).getTarget()=vanon_vma_335)
}

predicate func_3(Function func) {
	exists(PostfixIncrExpr target_3 |
		target_3.getOperand().(PointerFieldAccess).getTarget().getName()="degree"
		and target_3.getOperand().(PointerFieldAccess).getQualifier() instanceof PointerFieldAccess
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(Parameter vvma_332, Variable vavc_334, Variable vanon_vma_335) {
	exists(FunctionCall target_4 |
		target_4.getTarget().hasName("anon_vma_chain_link")
		and target_4.getArgument(0).(VariableAccess).getTarget()=vvma_332
		and target_4.getArgument(1).(VariableAccess).getTarget()=vavc_334
		and target_4.getArgument(2).(VariableAccess).getTarget()=vanon_vma_335)
}

from Function func, Parameter vvma_332, Variable vavc_334, Variable vanon_vma_335
where
not func_0(vanon_vma_335)
and not func_1(func)
and func_2(vanon_vma_335)
and func_3(func)
and vanon_vma_335.getType().hasName("anon_vma *")
and func_4(vvma_332, vavc_334, vanon_vma_335)
and vvma_332.getParentScope+() = func
and vavc_334.getParentScope+() = func
and vanon_vma_335.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
