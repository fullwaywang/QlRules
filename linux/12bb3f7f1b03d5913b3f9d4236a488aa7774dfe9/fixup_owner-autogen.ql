/**
 * @name linux-12bb3f7f1b03d5913b3f9d4236a488aa7774dfe9-fixup_owner
 * @id cpp/linux/12bb3f7f1b03d5913b3f9d4236a488aa7774dfe9/fixup-owner
 * @description linux-12bb3f7f1b03d5913b3f9d4236a488aa7774dfe9-fixup_owner 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="1"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Parameter vq_2524) {
	exists(ReturnStmt target_1 |
		target_1.getExpr() instanceof FunctionCall
		and target_1.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="owner"
		and target_1.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="pi_state"
		and target_1.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vq_2524
		and target_1.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("get_current"))
}

predicate func_2(Parameter vq_2524) {
	exists(ErrorExpr target_2 |
		target_2.getType() instanceof ErroneousType
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("printk")
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="3fixup_owner: ret = %d pi-mutex: %p pi-state %p\n"
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getTarget().getName()="owner"
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="pi_mutex"
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="pi_state"
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vq_2524
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="owner"
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="pi_state"
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vq_2524)
}

predicate func_3(Parameter vuaddr_2524, Parameter vq_2524) {
	exists(FunctionCall target_3 |
		target_3.getTarget().hasName("fixup_pi_state_owner")
		and target_3.getArgument(0).(VariableAccess).getTarget()=vuaddr_2524
		and target_3.getArgument(1).(VariableAccess).getTarget()=vq_2524
		and target_3.getArgument(2).(FunctionCall).getTarget().hasName("get_current"))
}

predicate func_4(Parameter vuaddr_2524, Parameter vq_2524) {
	exists(FunctionCall target_4 |
		target_4.getTarget().hasName("fixup_pi_state_owner")
		and target_4.getArgument(0).(VariableAccess).getTarget()=vuaddr_2524
		and target_4.getArgument(1).(VariableAccess).getTarget()=vq_2524
		and target_4.getArgument(2).(Literal).getValue()="0")
}

predicate func_5(Function func) {
	exists(Literal target_5 |
		target_5.getValue()="0"
		and target_5.getEnclosingFunction() = func)
}

predicate func_6(Function func) {
	exists(DeclStmt target_6 |
		target_6.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr() instanceof Literal
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_6)
}

predicate func_7(Parameter vq_2524, Variable vret_2526) {
	exists(ExprStmt target_7 |
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_2526
		and target_7.getExpr().(AssignExpr).getRValue() instanceof FunctionCall
		and target_7.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="owner"
		and target_7.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="pi_state"
		and target_7.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vq_2524
		and target_7.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("get_current"))
}

predicate func_8(Parameter vlocked_2524, Variable vret_2526) {
	exists(ConditionalExpr target_8 |
		target_8.getCondition().(VariableAccess).getTarget()=vret_2526
		and target_8.getThen().(VariableAccess).getTarget()=vret_2526
		and target_8.getElse().(VariableAccess).getTarget()=vlocked_2524)
}

predicate func_9(Variable vret_2526) {
	exists(AssignExpr target_9 |
		target_9.getLValue().(VariableAccess).getTarget()=vret_2526
		and target_9.getRValue() instanceof FunctionCall)
}

predicate func_10(Variable vret_2526) {
	exists(VariableAccess target_10 |
		target_10.getTarget()=vret_2526)
}

predicate func_11(Parameter vq_2524, Variable vret_2526) {
	exists(ExprStmt target_11 |
		target_11.getExpr().(FunctionCall).getTarget().hasName("printk")
		and target_11.getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="3fixup_owner: ret = %d pi-mutex: %p pi-state %p\n"
		and target_11.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vret_2526
		and target_11.getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getTarget().getName()="owner"
		and target_11.getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="pi_mutex"
		and target_11.getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="pi_state"
		and target_11.getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vq_2524
		and target_11.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="owner"
		and target_11.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="pi_state"
		and target_11.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vq_2524
		and target_11.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("rt_mutex_owner")
		and target_11.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="pi_mutex"
		and target_11.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="pi_state"
		and target_11.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vq_2524
		and target_11.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("get_current"))
}

from Function func, Parameter vuaddr_2524, Parameter vq_2524, Parameter vlocked_2524, Variable vret_2526
where
not func_0(func)
and not func_1(vq_2524)
and not func_2(vq_2524)
and func_3(vuaddr_2524, vq_2524)
and func_4(vuaddr_2524, vq_2524)
and func_5(func)
and func_6(func)
and func_7(vq_2524, vret_2526)
and func_8(vlocked_2524, vret_2526)
and func_9(vret_2526)
and func_10(vret_2526)
and func_11(vq_2524, vret_2526)
and vuaddr_2524.getType().hasName("u32 *")
and vq_2524.getType().hasName("futex_q *")
and vlocked_2524.getType().hasName("int")
and vret_2526.getType().hasName("int")
and vuaddr_2524.getParentScope+() = func
and vq_2524.getParentScope+() = func
and vlocked_2524.getParentScope+() = func
and vret_2526.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
