/**
 * @name linux-84ecc2f6eb1cb12e6d44818f94fa49b50f06e6ac-con_insert_unipair
 * @id cpp/linux/84ecc2f6eb1cb12e6d44818f94fa49b50f06e6ac/con_insert_unipair
 * @description linux-84ecc2f6eb1cb12e6d44818f94fa49b50f06e6ac-con_insert_unipair 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vp1_478, Variable vp2_478) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("kfree")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp1_478
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vp2_478)
}

predicate func_1(Variable vp2_478, Variable vn_477, Parameter vp_475) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="uni_pgdir"
		and target_1.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_475
		and target_1.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vn_477
		and target_1.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vp2_478)
}

predicate func_2(Variable vp2_478) {
	exists(ReturnStmt target_2 |
		target_2.getExpr().(UnaryMinusExpr).getValue()="-12"
		and target_2.getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="12"
		and target_2.getParent().(IfStmt).getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vp2_478)
}

predicate func_3(Variable vp1_478, Variable vn_477) {
	exists(ArrayExpr target_3 |
		target_3.getArrayBase().(VariableAccess).getTarget()=vp1_478
		and target_3.getArrayOffset().(VariableAccess).getTarget()=vn_477
		and target_3.getParent().(AssignExpr).getLValue() = target_3
		and target_3.getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("kmalloc_array")
		and target_3.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(Literal).getValue()="64"
		and target_3.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(SizeofTypeOperator).getType() instanceof LongType
		and target_3.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(SizeofTypeOperator).getValue()="2"
		and target_3.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(BitwiseOrExpr).getValue()="3264"
		and target_3.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(Literal).getValue()="1024"
		and target_3.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(Literal).getValue()="2048"
		and target_3.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(Literal).getValue()="64"
		and target_3.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(BitwiseOrExpr).getRightOperand().(Literal).getValue()="128")
}

predicate func_5(Parameter vp_475) {
	exists(PointerFieldAccess target_5 |
		target_5.getTarget().getName()="uni_pgdir"
		and target_5.getQualifier().(VariableAccess).getTarget()=vp_475)
}

from Function func, Variable vp1_478, Variable vp2_478, Variable vn_477, Parameter vp_475
where
not func_0(vp1_478, vp2_478)
and not func_1(vp2_478, vn_477, vp_475)
and func_2(vp2_478)
and vp1_478.getType().hasName("u16 **")
and func_3(vp1_478, vn_477)
and vp2_478.getType().hasName("u16 *")
and vn_477.getType().hasName("int")
and vp_475.getType().hasName("uni_pagedir *")
and func_5(vp_475)
and vp1_478.getParentScope+() = func
and vp2_478.getParentScope+() = func
and vn_477.getParentScope+() = func
and vp_475.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
