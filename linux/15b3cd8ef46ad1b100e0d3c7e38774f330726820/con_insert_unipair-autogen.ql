/**
 * @name linux-15b3cd8ef46ad1b100e0d3c7e38774f330726820-con_insert_unipair
 * @id cpp/linux/15b3cd8ef46ad1b100e0d3c7e38774f330726820/con_insert_unipair
 * @description linux-15b3cd8ef46ad1b100e0d3c7e38774f330726820-con_insert_unipair 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vp2_478) {
	exists(ReturnStmt target_0 |
		target_0.getExpr().(UnaryMinusExpr).getValue()="-12"
		and target_0.getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="12"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vp2_478)
}

predicate func_1(Variable vp1_478, Variable vp2_478) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("kfree")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp1_478
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vp2_478)
}

predicate func_2(Variable vn_477, Variable vp2_478, Parameter vp_475) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="uni_pgdir"
		and target_2.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_475
		and target_2.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vn_477
		and target_2.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vp2_478)
}

from Function func, Variable vn_477, Variable vp1_478, Variable vp2_478, Parameter vp_475
where
func_0(vp2_478)
and func_1(vp1_478, vp2_478)
and func_2(vn_477, vp2_478, vp_475)
and vn_477.getType().hasName("int")
and vp1_478.getType().hasName("u16 **")
and vp2_478.getType().hasName("u16 *")
and vp_475.getType().hasName("uni_pagedir *")
and vn_477.getParentScope+() = func
and vp1_478.getParentScope+() = func
and vp2_478.getParentScope+() = func
and vp_475.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
