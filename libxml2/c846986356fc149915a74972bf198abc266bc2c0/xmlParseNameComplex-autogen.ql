/**
 * @name libxml2-c846986356fc149915a74972bf198abc266bc2c0-xmlParseNameComplex
 * @id cpp/libxml2/c846986356fc149915a74972bf198abc266bc2c0/xmlParseNameComplex
 * @description libxml2-c846986356fc149915a74972bf198abc266bc2c0-parser.c-xmlParseNameComplex CVE-2022-40303
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

predicate func_1(Variable vlen_3202, Variable vl_3202, BlockStmt target_11, ExprStmt target_7, LogicalAndExpr target_10, AddressOfExpr target_12) {
	exists(RelationalOperation target_1 |
		 (target_1 instanceof GEExpr or target_1 instanceof LEExpr)
		and target_1.getLesserOperand().(VariableAccess).getTarget()=vlen_3202
		and target_1.getGreaterOperand().(SubExpr).getLeftOperand().(Literal).getValue()="2147483647"
		and target_1.getGreaterOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vl_3202
		and target_1.getParent().(IfStmt).getThen()=target_11
		and target_7.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getLesserOperand().(VariableAccess).getLocation())
		and target_1.getLesserOperand().(VariableAccess).getLocation().isBefore(target_10.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_12.getOperand().(VariableAccess).getLocation().isBefore(target_1.getGreaterOperand().(SubExpr).getRightOperand().(VariableAccess).getLocation()))
}

predicate func_2(Variable vlen_3202, Variable vl_3202, ExprStmt target_6, ExprStmt target_7, AddressOfExpr target_13) {
	exists(IfStmt target_2 |
		target_2.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vlen_3202
		and target_2.getCondition().(RelationalOperation).getGreaterOperand().(SubExpr).getLeftOperand().(Literal).getValue()="2147483647"
		and target_2.getCondition().(RelationalOperation).getGreaterOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vl_3202
		and target_2.getThen() instanceof ExprStmt
		and target_6.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_2.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_2.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_7.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getLocation())
		and target_13.getOperand().(VariableAccess).getLocation().isBefore(target_2.getCondition().(RelationalOperation).getGreaterOperand().(SubExpr).getRightOperand().(VariableAccess).getLocation()))
}

predicate func_3(Parameter vctxt_3201, Variable vlen_3202, LogicalAndExpr target_10, RelationalOperation target_14, Function func) {
	exists(IfStmt target_3 |
		target_3.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlen_3202
		and target_3.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("int")
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("xmlFatalErr")
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_3201
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Name"
		and target_3.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_3 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_3)
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_14.getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_5(Variable vlen_3202, Variable vl_3202, ExprStmt target_5) {
		target_5.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vlen_3202
		and target_5.getExpr().(AssignAddExpr).getRValue().(VariableAccess).getTarget()=vl_3202
}

predicate func_6(Variable vlen_3202, Variable vl_3202, EqualityOperation target_15, ExprStmt target_6) {
		target_6.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vlen_3202
		and target_6.getExpr().(AssignAddExpr).getRValue().(VariableAccess).getTarget()=vl_3202
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_15
}

predicate func_7(Variable vlen_3202, Variable vl_3202, ExprStmt target_7) {
		target_7.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vlen_3202
		and target_7.getExpr().(AssignAddExpr).getRValue().(VariableAccess).getTarget()=vl_3202
}

predicate func_8(Parameter vctxt_3201, BitwiseAndExpr target_8) {
		target_8.getLeftOperand().(PointerFieldAccess).getTarget().getName()="options"
		and target_8.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_3201
}

predicate func_10(Variable vlen_3202, BlockStmt target_11, LogicalAndExpr target_10) {
		target_10.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlen_3202
		and target_10.getAnOperand().(RelationalOperation).getLesserOperand() instanceof Literal
		and target_10.getAnOperand().(EqualityOperation).getAnOperand() instanceof BitwiseAndExpr
		and target_10.getAnOperand().(EqualityOperation).getAnOperand() instanceof Literal
		and target_10.getParent().(IfStmt).getThen()=target_11
}

predicate func_11(Parameter vctxt_3201, BlockStmt target_11) {
		target_11.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("xmlFatalErr")
		and target_11.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_3201
		and target_11.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Name"
		and target_11.getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
}

predicate func_12(Variable vl_3202, AddressOfExpr target_12) {
		target_12.getOperand().(VariableAccess).getTarget()=vl_3202
}

predicate func_13(Variable vl_3202, AddressOfExpr target_13) {
		target_13.getOperand().(VariableAccess).getTarget()=vl_3202
}

predicate func_14(Parameter vctxt_3201, Variable vlen_3202, RelationalOperation target_14) {
		 (target_14 instanceof GTExpr or target_14 instanceof LTExpr)
		and target_14.getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(PointerFieldAccess).getTarget().getName()="cur"
		and target_14.getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_14.getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_3201
		and target_14.getLesserOperand().(PointerArithmeticOperation).getRightOperand().(PointerFieldAccess).getTarget().getName()="base"
		and target_14.getLesserOperand().(PointerArithmeticOperation).getRightOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_14.getLesserOperand().(PointerArithmeticOperation).getRightOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_3201
		and target_14.getGreaterOperand().(VariableAccess).getTarget()=vlen_3202
}

predicate func_15(Parameter vctxt_3201, EqualityOperation target_15) {
		target_15.getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="options"
		and target_15.getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_3201
		and target_15.getAnOperand().(Literal).getValue()="0"
}

from Function func, Parameter vctxt_3201, Variable vlen_3202, Variable vl_3202, Literal target_0, ExprStmt target_5, ExprStmt target_6, ExprStmt target_7, BitwiseAndExpr target_8, LogicalAndExpr target_10, BlockStmt target_11, AddressOfExpr target_12, AddressOfExpr target_13, RelationalOperation target_14, EqualityOperation target_15
where
func_0(func, target_0)
and not func_1(vlen_3202, vl_3202, target_11, target_7, target_10, target_12)
and not func_2(vlen_3202, vl_3202, target_6, target_7, target_13)
and not func_3(vctxt_3201, vlen_3202, target_10, target_14, func)
and func_5(vlen_3202, vl_3202, target_5)
and func_6(vlen_3202, vl_3202, target_15, target_6)
and func_7(vlen_3202, vl_3202, target_7)
and func_8(vctxt_3201, target_8)
and func_10(vlen_3202, target_11, target_10)
and func_11(vctxt_3201, target_11)
and func_12(vl_3202, target_12)
and func_13(vl_3202, target_13)
and func_14(vctxt_3201, vlen_3202, target_14)
and func_15(vctxt_3201, target_15)
and vctxt_3201.getType().hasName("xmlParserCtxtPtr")
and vlen_3202.getType().hasName("int")
and vl_3202.getType().hasName("int")
and vctxt_3201.getParentScope+() = func
and vlen_3202.getParentScope+() = func
and vl_3202.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
