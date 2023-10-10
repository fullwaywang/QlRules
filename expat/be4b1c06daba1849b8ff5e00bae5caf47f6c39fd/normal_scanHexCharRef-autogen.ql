/**
 * @name expat-be4b1c06daba1849b8ff5e00bae5caf47f6c39fd-normal_scanHexCharRef
 * @id cpp/expat/be4b1c06daba1849b8ff5e00bae5caf47f6c39fd/normal-scanHexCharRef
 * @description expat-be4b1c06daba1849b8ff5e00bae5caf47f6c39fd-expat/lib/xmltok_impl.c-normal_scanHexCharRef CVE-2016-0718
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vend_433, Parameter vptr_432, BlockStmt target_8, EqualityOperation target_7, ArrayExpr target_9) {
	exists(RelationalOperation target_0 |
		 (target_0 instanceof GTExpr or target_0 instanceof LTExpr)
		and target_0.getLesserOperand().(VariableAccess).getTarget()=vptr_432
		and target_0.getGreaterOperand().(VariableAccess).getTarget()=vend_433
		and target_0.getParent().(IfStmt).getThen()=target_8
		and target_0.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_7.getAnOperand().(VariableAccess).getLocation())
		and target_0.getLesserOperand().(VariableAccess).getLocation().isBefore(target_9.getArrayOffset().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vend_433, Parameter vptr_432, BlockStmt target_10, EqualityOperation target_6, ExprStmt target_11) {
	exists(RelationalOperation target_1 |
		 (target_1 instanceof GTExpr or target_1 instanceof LTExpr)
		and target_1.getLesserOperand().(VariableAccess).getTarget()=vptr_432
		and target_1.getGreaterOperand().(VariableAccess).getTarget()=vend_433
		and target_1.getParent().(ForStmt).getStmt()=target_10
		and target_6.getAnOperand().(VariableAccess).getLocation().isBefore(target_1.getGreaterOperand().(VariableAccess).getLocation())
		and target_11.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getLesserOperand().(VariableAccess).getLocation()))
}

/*predicate func_2(Parameter vend_433, Parameter vptr_432, BlockStmt target_8, VariableAccess target_2) {
		target_2.getTarget()=vptr_432
		and target_2.getParent().(NEExpr).getAnOperand().(VariableAccess).getTarget()=vend_433
		and target_2.getParent().(NEExpr).getParent().(IfStmt).getThen()=target_8
}

*/
/*predicate func_3(Parameter vend_433, Parameter vptr_432, BlockStmt target_8, VariableAccess target_3) {
		target_3.getTarget()=vend_433
		and target_3.getParent().(NEExpr).getAnOperand().(VariableAccess).getTarget()=vptr_432
		and target_3.getParent().(NEExpr).getParent().(IfStmt).getThen()=target_8
}

*/
/*predicate func_4(Parameter vend_433, Parameter vptr_432, BlockStmt target_10, VariableAccess target_4) {
		target_4.getTarget()=vptr_432
		and target_4.getParent().(NEExpr).getAnOperand().(VariableAccess).getTarget()=vend_433
		and target_4.getParent().(NEExpr).getParent().(ForStmt).getStmt()=target_10
}

*/
/*predicate func_5(Parameter vend_433, Parameter vptr_432, BlockStmt target_10, VariableAccess target_5) {
		target_5.getTarget()=vend_433
		and target_5.getParent().(NEExpr).getAnOperand().(VariableAccess).getTarget()=vptr_432
		and target_5.getParent().(NEExpr).getParent().(ForStmt).getStmt()=target_10
}

*/
predicate func_6(Parameter vend_433, Parameter vptr_432, BlockStmt target_8, EqualityOperation target_7, ArrayExpr target_9, EqualityOperation target_6) {
		target_6.getAnOperand().(VariableAccess).getTarget()=vptr_432
		and target_6.getAnOperand().(VariableAccess).getTarget()=vend_433
		and target_6.getParent().(IfStmt).getThen()=target_8
		and target_6.getAnOperand().(VariableAccess).getLocation().isBefore(target_7.getAnOperand().(VariableAccess).getLocation())
		and target_6.getAnOperand().(VariableAccess).getLocation().isBefore(target_9.getArrayOffset().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
}

predicate func_7(Parameter vend_433, Parameter vptr_432, BlockStmt target_10, EqualityOperation target_6, EqualityOperation target_7) {
		target_7.getAnOperand().(VariableAccess).getTarget()=vptr_432
		and target_7.getAnOperand().(VariableAccess).getTarget()=vend_433
		and target_7.getParent().(ForStmt).getStmt()=target_10
		and target_6.getAnOperand().(VariableAccess).getLocation().isBefore(target_7.getAnOperand().(VariableAccess).getLocation())
}

predicate func_8(Parameter vptr_432, BlockStmt target_8) {
		target_8.getStmt(0).(BlockStmt).getStmt(0).(SwitchStmt).getExpr().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="type"
		and target_8.getStmt(0).(BlockStmt).getStmt(0).(SwitchStmt).getExpr().(ArrayExpr).getArrayOffset().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vptr_432
		and target_8.getStmt(0).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(2).(BreakStmt).toString() = "break;"
		and target_8.getStmt(0).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(3).(SwitchCase).toString() = "default: "
		and target_8.getStmt(0).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vptr_432
		and target_8.getStmt(0).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(5).(ReturnStmt).getExpr().(Literal).getValue()="0"
}

predicate func_9(Parameter vptr_432, ArrayExpr target_9) {
		target_9.getArrayBase().(PointerFieldAccess).getTarget().getName()="type"
		and target_9.getArrayOffset().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vptr_432
}

predicate func_10(Parameter vptr_432, BlockStmt target_10) {
		target_10.getStmt(0).(BlockStmt).getStmt(0).(SwitchStmt).getExpr().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="type"
		and target_10.getStmt(0).(BlockStmt).getStmt(0).(SwitchStmt).getExpr().(ArrayExpr).getArrayOffset().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vptr_432
		and target_10.getStmt(0).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(2).(BreakStmt).toString() = "break;"
		and target_10.getStmt(0).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(5).(ReturnStmt).getExpr().(Literal).getValue()="10"
		and target_10.getStmt(0).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(6).(SwitchCase).toString() = "default: "
		and target_10.getStmt(0).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(7).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vptr_432
		and target_10.getStmt(0).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(8).(ReturnStmt).getExpr().(Literal).getValue()="0"
}

predicate func_11(Parameter vptr_432, ExprStmt target_11) {
		target_11.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vptr_432
		and target_11.getExpr().(AssignPointerAddExpr).getRValue().(Literal).getValue()="1"
}

from Function func, Parameter vend_433, Parameter vptr_432, EqualityOperation target_6, EqualityOperation target_7, BlockStmt target_8, ArrayExpr target_9, BlockStmt target_10, ExprStmt target_11
where
not func_0(vend_433, vptr_432, target_8, target_7, target_9)
and not func_1(vend_433, vptr_432, target_10, target_6, target_11)
and func_6(vend_433, vptr_432, target_8, target_7, target_9, target_6)
and func_7(vend_433, vptr_432, target_10, target_6, target_7)
and func_8(vptr_432, target_8)
and func_9(vptr_432, target_9)
and func_10(vptr_432, target_10)
and func_11(vptr_432, target_11)
and vend_433.getType().hasName("const char *")
and vptr_432.getType().hasName("const char *")
and vend_433.getParentScope+() = func
and vptr_432.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
