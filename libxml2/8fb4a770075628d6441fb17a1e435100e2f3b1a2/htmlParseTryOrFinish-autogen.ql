/**
 * @name libxml2-8fb4a770075628d6441fb17a1e435100e2f3b1a2-htmlParseTryOrFinish
 * @id cpp/libxml2/8fb4a770075628d6441fb17a1e435100e2f3b1a2/htmlParseTryOrFinish
 * @description libxml2-8fb4a770075628d6441fb17a1e435100e2f3b1a2-HTMLparser.c-htmlParseTryOrFinish CVE-2015-8242
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vin_5279, ExprStmt target_6) {
	exists(AddressOfExpr target_0 |
		target_0.getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="cur"
		and target_0.getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vin_5279
		and target_0.getOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_0.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="characters"
		and target_0.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="sax"
		and target_0.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("htmlParserCtxtPtr")
		and target_0.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="userData"
		and target_0.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("htmlParserCtxtPtr")
		and target_0.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getArgument(1) instanceof AddressOfExpr
		and target_0.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getArgument(2).(Literal).getValue()="1"
		and target_6.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vin_5279) {
	exists(AddressOfExpr target_1 |
		target_1.getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="cur"
		and target_1.getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vin_5279
		and target_1.getOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_1.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="ignorableWhitespace"
		and target_1.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="sax"
		and target_1.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("htmlParserCtxtPtr")
		and target_1.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="userData"
		and target_1.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("htmlParserCtxtPtr")
		and target_1.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getArgument(1) instanceof AddressOfExpr
		and target_1.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getArgument(2).(Literal).getValue()="1")
}

predicate func_2(Variable vin_5279, ExprStmt target_7) {
	exists(AddressOfExpr target_2 |
		target_2.getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="cur"
		and target_2.getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vin_5279
		and target_2.getOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_2.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="characters"
		and target_2.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="sax"
		and target_2.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("htmlParserCtxtPtr")
		and target_2.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="userData"
		and target_2.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("htmlParserCtxtPtr")
		and target_2.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getArgument(1) instanceof AddressOfExpr
		and target_2.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getArgument(2).(Literal).getValue()="1"
		and target_2.getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_7.getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_3(Variable vcur_5281, LogicalOrExpr target_8, AddressOfExpr target_4, AddressOfExpr target_3) {
		target_3.getOperand().(VariableAccess).getTarget()=vcur_5281
		and target_3.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="characters"
		and target_3.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="sax"
		and target_3.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("htmlParserCtxtPtr")
		and target_3.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="userData"
		and target_3.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("htmlParserCtxtPtr")
		and target_3.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getArgument(2).(Literal).getValue()="1"
		and target_8.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_3.getOperand().(VariableAccess).getLocation())
		and target_3.getOperand().(VariableAccess).getLocation().isBefore(target_4.getOperand().(VariableAccess).getLocation())
}

predicate func_4(Variable vcur_5281, AddressOfExpr target_3, AddressOfExpr target_5, AddressOfExpr target_4) {
		target_4.getOperand().(VariableAccess).getTarget()=vcur_5281
		and target_4.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="ignorableWhitespace"
		and target_4.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="sax"
		and target_4.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("htmlParserCtxtPtr")
		and target_4.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="userData"
		and target_4.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("htmlParserCtxtPtr")
		and target_4.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getArgument(2).(Literal).getValue()="1"
		and target_3.getOperand().(VariableAccess).getLocation().isBefore(target_4.getOperand().(VariableAccess).getLocation())
		and target_4.getOperand().(VariableAccess).getLocation().isBefore(target_5.getOperand().(VariableAccess).getLocation())
}

predicate func_5(Variable vcur_5281, AddressOfExpr target_4, AddressOfExpr target_5) {
		target_5.getOperand().(VariableAccess).getTarget()=vcur_5281
		and target_5.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="characters"
		and target_5.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="sax"
		and target_5.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("htmlParserCtxtPtr")
		and target_5.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="userData"
		and target_5.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("htmlParserCtxtPtr")
		and target_5.getParent().(VariableCall).getParent().(ExprStmt).getExpr().(VariableCall).getArgument(2).(Literal).getValue()="1"
		and target_4.getOperand().(VariableAccess).getLocation().isBefore(target_5.getOperand().(VariableAccess).getLocation())
}

predicate func_6(Variable vin_5279, Variable vcur_5281, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcur_5281
		and target_6.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="cur"
		and target_6.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vin_5279
		and target_6.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
}

predicate func_7(Variable vin_5279, ExprStmt target_7) {
		target_7.getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="cur"
		and target_7.getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vin_5279
}

predicate func_8(Variable vcur_5281, LogicalOrExpr target_8) {
		target_8.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vcur_5281
		and target_8.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="32"
		and target_8.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="9"
		and target_8.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vcur_5281
		and target_8.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vcur_5281
		and target_8.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="10"
		and target_8.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vcur_5281
		and target_8.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="13"
}

from Function func, Variable vin_5279, Variable vcur_5281, AddressOfExpr target_3, AddressOfExpr target_4, AddressOfExpr target_5, ExprStmt target_6, ExprStmt target_7, LogicalOrExpr target_8
where
not func_0(vin_5279, target_6)
and not func_1(vin_5279)
and not func_2(vin_5279, target_7)
and func_3(vcur_5281, target_8, target_4, target_3)
and func_4(vcur_5281, target_3, target_5, target_4)
and func_5(vcur_5281, target_4, target_5)
and func_6(vin_5279, vcur_5281, target_6)
and func_7(vin_5279, target_7)
and func_8(vcur_5281, target_8)
and vin_5279.getType().hasName("htmlParserInputPtr")
and vcur_5281.getType().hasName("xmlChar")
and vin_5279.(LocalVariable).getFunction() = func
and vcur_5281.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
