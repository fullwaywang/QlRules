/**
 * @name expat-be4b1c06daba1849b8ff5e00bae5caf47f6c39fd-normal_scanCharRef
 * @id cpp/expat/be4b1c06daba1849b8ff5e00bae5caf47f6c39fd/normal-scanCharRef
 * @description expat-be4b1c06daba1849b8ff5e00bae5caf47f6c39fd-expat/lib/xmltok_impl.c-normal_scanCharRef CVE-2016-0718
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vend_465, Parameter vptr_464, BlockStmt target_8, FunctionCall target_9, EqualityOperation target_10) {
	exists(RelationalOperation target_0 |
		 (target_0 instanceof GTExpr or target_0 instanceof LTExpr)
		and target_0.getLesserOperand().(VariableAccess).getTarget()=vptr_464
		and target_0.getGreaterOperand().(VariableAccess).getTarget()=vend_465
		and target_0.getParent().(IfStmt).getThen()=target_8
		and target_0.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_9.getArgument(2).(VariableAccess).getLocation())
		and target_0.getLesserOperand().(VariableAccess).getLocation().isBefore(target_10.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vend_465, Parameter vptr_464, BlockStmt target_11, FunctionCall target_9, ExprStmt target_12) {
	exists(RelationalOperation target_1 |
		 (target_1 instanceof GTExpr or target_1 instanceof LTExpr)
		and target_1.getLesserOperand().(VariableAccess).getTarget()=vptr_464
		and target_1.getGreaterOperand().(VariableAccess).getTarget()=vend_465
		and target_1.getParent().(ForStmt).getStmt()=target_11
		and target_9.getArgument(2).(VariableAccess).getLocation().isBefore(target_1.getGreaterOperand().(VariableAccess).getLocation())
		and target_12.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getLesserOperand().(VariableAccess).getLocation()))
}

/*predicate func_2(Parameter vend_465, Parameter vptr_464, BlockStmt target_8, VariableAccess target_2) {
		target_2.getTarget()=vptr_464
		and target_2.getParent().(NEExpr).getAnOperand().(VariableAccess).getTarget()=vend_465
		and target_2.getParent().(NEExpr).getParent().(IfStmt).getThen()=target_8
}

*/
/*predicate func_3(Parameter vend_465, Parameter vptr_464, BlockStmt target_8, VariableAccess target_3) {
		target_3.getTarget()=vend_465
		and target_3.getParent().(NEExpr).getAnOperand().(VariableAccess).getTarget()=vptr_464
		and target_3.getParent().(NEExpr).getParent().(IfStmt).getThen()=target_8
}

*/
/*predicate func_4(Parameter vend_465, Parameter vptr_464, BlockStmt target_11, VariableAccess target_4) {
		target_4.getTarget()=vptr_464
		and target_4.getParent().(NEExpr).getAnOperand().(VariableAccess).getTarget()=vend_465
		and target_4.getParent().(NEExpr).getParent().(ForStmt).getStmt()=target_11
}

*/
/*predicate func_5(Parameter vend_465, Parameter vptr_464, BlockStmt target_11, VariableAccess target_5) {
		target_5.getTarget()=vend_465
		and target_5.getParent().(NEExpr).getAnOperand().(VariableAccess).getTarget()=vptr_464
		and target_5.getParent().(NEExpr).getParent().(ForStmt).getStmt()=target_11
}

*/
predicate func_6(Parameter vend_465, Parameter vptr_464, BlockStmt target_8, FunctionCall target_9, EqualityOperation target_10, EqualityOperation target_6) {
		target_6.getAnOperand().(VariableAccess).getTarget()=vptr_464
		and target_6.getAnOperand().(VariableAccess).getTarget()=vend_465
		and target_6.getParent().(IfStmt).getThen()=target_8
		and target_6.getAnOperand().(VariableAccess).getLocation().isBefore(target_9.getArgument(2).(VariableAccess).getLocation())
		and target_6.getAnOperand().(VariableAccess).getLocation().isBefore(target_10.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
}

predicate func_7(Parameter vend_465, Parameter vptr_464, BlockStmt target_11, FunctionCall target_9, EqualityOperation target_7) {
		target_7.getAnOperand().(VariableAccess).getTarget()=vptr_464
		and target_7.getAnOperand().(VariableAccess).getTarget()=vend_465
		and target_7.getParent().(ForStmt).getStmt()=target_11
		and target_9.getArgument(2).(VariableAccess).getLocation().isBefore(target_7.getAnOperand().(VariableAccess).getLocation())
}

predicate func_8(Parameter vend_465, Parameter vptr_464, BlockStmt target_8) {
		target_8.getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vptr_464
		and target_8.getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="120"
		and target_8.getStmt(0).(IfStmt).getThen().(ReturnStmt).getExpr().(FunctionCall).getTarget().hasName("normal_scanHexCharRef")
		and target_8.getStmt(0).(IfStmt).getThen().(ReturnStmt).getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vptr_464
		and target_8.getStmt(0).(IfStmt).getThen().(ReturnStmt).getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="1"
		and target_8.getStmt(0).(IfStmt).getThen().(ReturnStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vend_465
}

predicate func_9(Parameter vend_465, Parameter vptr_464, FunctionCall target_9) {
		target_9.getTarget().hasName("normal_scanHexCharRef")
		and target_9.getArgument(1).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vptr_464
		and target_9.getArgument(1).(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="1"
		and target_9.getArgument(2).(VariableAccess).getTarget()=vend_465
}

predicate func_10(Parameter vptr_464, EqualityOperation target_10) {
		target_10.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vptr_464
		and target_10.getAnOperand().(Literal).getValue()="120"
}

predicate func_11(Parameter vptr_464, BlockStmt target_11) {
		target_11.getStmt(0).(BlockStmt).getStmt(0).(SwitchStmt).getExpr().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="type"
		and target_11.getStmt(0).(BlockStmt).getStmt(0).(SwitchStmt).getExpr().(ArrayExpr).getArrayOffset().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vptr_464
		and target_11.getStmt(0).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(1).(BreakStmt).toString() = "break;"
		and target_11.getStmt(0).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(4).(ReturnStmt).getExpr().(Literal).getValue()="10"
		and target_11.getStmt(0).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(5).(SwitchCase).toString() = "default: "
		and target_11.getStmt(0).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(6).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vptr_464
		and target_11.getStmt(0).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(7).(ReturnStmt).getExpr().(Literal).getValue()="0"
}

predicate func_12(Parameter vptr_464, ExprStmt target_12) {
		target_12.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vptr_464
		and target_12.getExpr().(AssignPointerAddExpr).getRValue().(Literal).getValue()="1"
}

from Function func, Parameter vend_465, Parameter vptr_464, EqualityOperation target_6, EqualityOperation target_7, BlockStmt target_8, FunctionCall target_9, EqualityOperation target_10, BlockStmt target_11, ExprStmt target_12
where
not func_0(vend_465, vptr_464, target_8, target_9, target_10)
and not func_1(vend_465, vptr_464, target_11, target_9, target_12)
and func_6(vend_465, vptr_464, target_8, target_9, target_10, target_6)
and func_7(vend_465, vptr_464, target_11, target_9, target_7)
and func_8(vend_465, vptr_464, target_8)
and func_9(vend_465, vptr_464, target_9)
and func_10(vptr_464, target_10)
and func_11(vptr_464, target_11)
and func_12(vptr_464, target_12)
and vend_465.getType().hasName("const char *")
and vptr_464.getType().hasName("const char *")
and vend_465.getParentScope+() = func
and vptr_464.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
