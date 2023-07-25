/**
 * @name libxml2-a820dbeac29d330bae4be05d9ecd939ad6b4aa33-htmlParseName
 * @id cpp/libxml2/a820dbeac29d330bae4be05d9ecd939ad6b4aa33/htmlParseName
 * @description libxml2-a820dbeac29d330bae4be05d9ecd939ad6b4aa33-HTMLparser.c-htmlParseName CVE-2016-1839
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vctxt_2453, Variable vin_2454, LogicalOrExpr target_1, ExprStmt target_2, ExprStmt target_3, ExprStmt target_4, LogicalAndExpr target_5) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vin_2454
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="end"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_2453
		and target_0.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_2.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getRightOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_4.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_5.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vin_2454, LogicalOrExpr target_1) {
		target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vin_2454
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(HexLiteral).getValue()="97"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vin_2454
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(HexLiteral).getValue()="122"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vin_2454
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(HexLiteral).getValue()="65"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vin_2454
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(HexLiteral).getValue()="90"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vin_2454
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="95"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vin_2454
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="58"
}

predicate func_2(Parameter vctxt_2453, Variable vin_2454, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vin_2454
		and target_2.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="cur"
		and target_2.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_2.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_2453
}

predicate func_3(Parameter vctxt_2453, Variable vin_2454, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_3.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vin_2454
		and target_3.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getRightOperand().(PointerFieldAccess).getTarget().getName()="cur"
		and target_3.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getRightOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_3.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getRightOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_2453
}

predicate func_4(Variable vin_2454, ExprStmt target_4) {
		target_4.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vin_2454
}

predicate func_5(Variable vin_2454, LogicalAndExpr target_5) {
		target_5.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vin_2454
		and target_5.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_5.getAnOperand().(RelationalOperation).getLesserOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vin_2454
		and target_5.getAnOperand().(RelationalOperation).getGreaterOperand().(HexLiteral).getValue()="128"
}

from Function func, Parameter vctxt_2453, Variable vin_2454, LogicalOrExpr target_1, ExprStmt target_2, ExprStmt target_3, ExprStmt target_4, LogicalAndExpr target_5
where
not func_0(vctxt_2453, vin_2454, target_1, target_2, target_3, target_4, target_5)
and func_1(vin_2454, target_1)
and func_2(vctxt_2453, vin_2454, target_2)
and func_3(vctxt_2453, vin_2454, target_3)
and func_4(vin_2454, target_4)
and func_5(vin_2454, target_5)
and vctxt_2453.getType().hasName("htmlParserCtxtPtr")
and vin_2454.getType().hasName("const xmlChar *")
and vctxt_2453.getFunction() = func
and vin_2454.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
