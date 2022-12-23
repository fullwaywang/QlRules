/**
 * @name linux-2555283eb40df89945557273121e9393ef9b542b-__anon_vma_prepare
 * @id cpp/linux/2555283eb40df89945557273121e9393ef9b542b/--anon-vma-prepare
 * @description linux-2555283eb40df89945557273121e9393ef9b542b-__anon_vma_prepare 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vanon_vma_189) {
	exists(PostfixIncrExpr target_0 |
		target_0.getOperand().(PointerFieldAccess).getTarget().getName()="num_children"
		and target_0.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vanon_vma_189)
}

predicate func_1(Parameter vvma_186, Variable vanon_vma_189) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="num_active_vmas"
		and target_1.getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vanon_vma_189
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getTarget().hasName("__builtin_expect")
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="anon_vma"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvma_186
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(1).(Literal).getValue()="1")
}

predicate func_3(Variable vanon_vma_189) {
	exists(PostfixIncrExpr target_3 |
		target_3.getOperand().(PointerFieldAccess).getTarget().getName()="degree"
		and target_3.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vanon_vma_189)
}

predicate func_4(Parameter vvma_186, Variable vanon_vma_189, Variable vavc_190) {
	exists(FunctionCall target_4 |
		target_4.getTarget().hasName("anon_vma_chain_link")
		and target_4.getArgument(0).(VariableAccess).getTarget()=vvma_186
		and target_4.getArgument(1).(VariableAccess).getTarget()=vavc_190
		and target_4.getArgument(2).(VariableAccess).getTarget()=vanon_vma_189)
}

from Function func, Parameter vvma_186, Variable vanon_vma_189, Variable vavc_190
where
not func_0(vanon_vma_189)
and not func_1(vvma_186, vanon_vma_189)
and func_3(vanon_vma_189)
and vvma_186.getType().hasName("vm_area_struct *")
and vanon_vma_189.getType().hasName("anon_vma *")
and func_4(vvma_186, vanon_vma_189, vavc_190)
and vavc_190.getType().hasName("anon_vma_chain *")
and vvma_186.getParentScope+() = func
and vanon_vma_189.getParentScope+() = func
and vavc_190.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
