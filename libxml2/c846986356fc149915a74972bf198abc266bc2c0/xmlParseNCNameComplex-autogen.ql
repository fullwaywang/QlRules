/**
 * @name libxml2-c846986356fc149915a74972bf198abc266bc2c0-xmlParseNCNameComplex
 * @id cpp/libxml2/c846986356fc149915a74972bf198abc266bc2c0/xmlParseNCNameComplex
 * @description libxml2-c846986356fc149915a74972bf198abc266bc2c0-parser.c-xmlParseNCNameComplex CVE-2022-40303
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
		target_0.getValue()="0"
		and not target_0.getValue()="10000000"
		and target_0.getParent().(EQExpr).getParent().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Function func, Literal target_1) {
		target_1.getValue()="50000"
		and not target_1.getValue()="2147483647"
		and target_1.getParent().(GTExpr).getParent().(LogicalAndExpr).getAnOperand() instanceof RelationalOperation
		and target_1.getEnclosingFunction() = func
}

predicate func_2(Variable vlen_3384, Variable vl_3384, BlockStmt target_12, ExprStmt target_7, FunctionCall target_13, AddressOfExpr target_14) {
	exists(RelationalOperation target_2 |
		 (target_2 instanceof GEExpr or target_2 instanceof LEExpr)
		and target_2.getLesserOperand().(VariableAccess).getTarget()=vlen_3384
		and target_2.getGreaterOperand().(SubExpr).getLeftOperand().(Literal).getValue()="2147483647"
		and target_2.getGreaterOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vl_3384
		and target_2.getParent().(IfStmt).getThen()=target_12
		and target_7.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_2.getLesserOperand().(VariableAccess).getLocation())
		and target_2.getLesserOperand().(VariableAccess).getLocation().isBefore(target_13.getArgument(2).(VariableAccess).getLocation())
		and target_14.getOperand().(VariableAccess).getLocation().isBefore(target_2.getGreaterOperand().(SubExpr).getRightOperand().(VariableAccess).getLocation()))
}

predicate func_4(Parameter vctxt_3383, LogicalAndExpr target_10, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("xmlFatalErr")
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_3383
		and target_4.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="NCName"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_10
}

predicate func_5(LogicalAndExpr target_10, Function func, ReturnStmt target_5) {
		target_5.getExpr().(Literal).getValue()="0"
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_10
		and target_5.getEnclosingFunction() = func
}

predicate func_6(Parameter vctxt_3383, BitwiseAndExpr target_6) {
		target_6.getLeftOperand().(PointerFieldAccess).getTarget().getName()="options"
		and target_6.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_3383
}

predicate func_7(Variable vlen_3384, Variable vl_3384, ExprStmt target_7) {
		target_7.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vlen_3384
		and target_7.getExpr().(AssignAddExpr).getRValue().(VariableAccess).getTarget()=vl_3384
}

predicate func_9(Variable vlen_3384, VariableAccess target_9) {
		target_9.getTarget()=vlen_3384
}

predicate func_10(Variable vlen_3384, BlockStmt target_12, LogicalAndExpr target_10) {
		target_10.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlen_3384
		and target_10.getAnOperand().(RelationalOperation).getLesserOperand() instanceof Literal
		and target_10.getAnOperand().(EqualityOperation).getAnOperand() instanceof BitwiseAndExpr
		and target_10.getAnOperand().(EqualityOperation).getAnOperand() instanceof Literal
		and target_10.getParent().(IfStmt).getThen()=target_12
}

predicate func_11(Parameter vctxt_3383, Variable vlen_3384, BlockStmt target_15, LogicalAndExpr target_11) {
		target_11.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlen_3384
		and target_11.getAnOperand().(RelationalOperation).getLesserOperand() instanceof Literal
		and target_11.getAnOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="options"
		and target_11.getAnOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_3383
		and target_11.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_11.getParent().(IfStmt).getThen()=target_15
}

predicate func_12(BlockStmt target_12) {
		target_12.getStmt(0) instanceof ExprStmt
		and target_12.getStmt(1) instanceof ReturnStmt
}

predicate func_13(Parameter vctxt_3383, Variable vlen_3384, FunctionCall target_13) {
		target_13.getTarget().hasName("xmlDictLookup")
		and target_13.getArgument(0).(PointerFieldAccess).getTarget().getName()="dict"
		and target_13.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_3383
		and target_13.getArgument(1).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="base"
		and target_13.getArgument(1).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_13.getArgument(1).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_3383
		and target_13.getArgument(2).(VariableAccess).getTarget()=vlen_3384
}

predicate func_14(Variable vl_3384, AddressOfExpr target_14) {
		target_14.getOperand().(VariableAccess).getTarget()=vl_3384
}

predicate func_15(Parameter vctxt_3383, BlockStmt target_15) {
		target_15.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("xmlFatalErr")
		and target_15.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_3383
		and target_15.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="NCName"
		and target_15.getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
}

from Function func, Parameter vctxt_3383, Variable vlen_3384, Variable vl_3384, Literal target_0, Literal target_1, ExprStmt target_4, ReturnStmt target_5, BitwiseAndExpr target_6, ExprStmt target_7, VariableAccess target_9, LogicalAndExpr target_10, LogicalAndExpr target_11, BlockStmt target_12, FunctionCall target_13, AddressOfExpr target_14, BlockStmt target_15
where
func_0(func, target_0)
and func_1(func, target_1)
and not func_2(vlen_3384, vl_3384, target_12, target_7, target_13, target_14)
and func_4(vctxt_3383, target_10, target_4)
and func_5(target_10, func, target_5)
and func_6(vctxt_3383, target_6)
and func_7(vlen_3384, vl_3384, target_7)
and func_9(vlen_3384, target_9)
and func_10(vlen_3384, target_12, target_10)
and func_11(vctxt_3383, vlen_3384, target_15, target_11)
and func_12(target_12)
and func_13(vctxt_3383, vlen_3384, target_13)
and func_14(vl_3384, target_14)
and func_15(vctxt_3383, target_15)
and vctxt_3383.getType().hasName("xmlParserCtxtPtr")
and vlen_3384.getType().hasName("int")
and vl_3384.getType().hasName("int")
and vctxt_3383.getParentScope+() = func
and vlen_3384.getParentScope+() = func
and vl_3384.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
