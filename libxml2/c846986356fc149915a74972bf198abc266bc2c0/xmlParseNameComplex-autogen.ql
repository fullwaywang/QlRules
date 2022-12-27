/**
 * @name libxml2-c846986356fc149915a74972bf198abc266bc2c0-xmlParseNameComplex
 * @id cpp/libxml2/c846986356fc149915a74972bf198abc266bc2c0/xmlParseNameComplex
 * @description libxml2-c846986356fc149915a74972bf198abc266bc2c0-xmlParseNameComplex CVE-2022-40303
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="0"
		and not target_0.getValue()="10000000"
		and target_0.getParent().(EQExpr).getParent().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(DeclStmt target_1 |
		target_1.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ConditionalExpr).getCondition() instanceof BitwiseAndExpr
		and target_1.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ConditionalExpr).getThen().(Literal).getValue()="10000000"
		and target_1.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ConditionalExpr).getElse() instanceof Literal
		and func.getEntryPoint().(BlockStmt).getStmt(3)=target_1)
}

predicate func_2(Variable vlen_3202, Variable vl_3202) {
	exists(RelationalOperation target_2 |
		 (target_2 instanceof GEExpr or target_2 instanceof LEExpr)
		and target_2.getLesserOperand().(VariableAccess).getTarget()=vlen_3202
		and target_2.getGreaterOperand().(SubExpr).getLeftOperand().(Literal).getValue()="2147483647"
		and target_2.getGreaterOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vl_3202
		and target_2.getParent().(IfStmt).getThen() instanceof ExprStmt)
}

predicate func_3(Variable vlen_3202, Variable vl_3202) {
	exists(IfStmt target_3 |
		target_3.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vlen_3202
		and target_3.getCondition().(RelationalOperation).getGreaterOperand().(SubExpr).getLeftOperand().(Literal).getValue()="2147483647"
		and target_3.getCondition().(RelationalOperation).getGreaterOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vl_3202
		and target_3.getThen() instanceof ExprStmt)
}

predicate func_4(Parameter vctxt_3201, Variable vlen_3202, Function func) {
	exists(IfStmt target_4 |
		target_4.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlen_3202
		and target_4.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("int")
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("xmlFatalErr")
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_3201
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Name"
		and target_4.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_4 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_4))
}

predicate func_6(Variable vlen_3202, Variable vl_3202) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vlen_3202
		and target_6.getExpr().(AssignAddExpr).getRValue().(VariableAccess).getTarget()=vl_3202)
}

predicate func_8(Parameter vctxt_3201) {
	exists(BitwiseAndExpr target_8 |
		target_8.getLeftOperand().(PointerFieldAccess).getTarget().getName()="options"
		and target_8.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_3201)
}

predicate func_9(Function func) {
	exists(Literal target_9 |
		target_9.getValue()="50000"
		and target_9.getEnclosingFunction() = func)
}

predicate func_10(Parameter vctxt_3201, Variable vlen_3202) {
	exists(LogicalAndExpr target_10 |
		target_10.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlen_3202
		and target_10.getAnOperand().(RelationalOperation).getLesserOperand() instanceof Literal
		and target_10.getAnOperand().(EqualityOperation).getAnOperand() instanceof BitwiseAndExpr
		and target_10.getAnOperand().(EqualityOperation).getAnOperand() instanceof Literal
		and target_10.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("xmlFatalErr")
		and target_10.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_3201
		and target_10.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Name"
		and target_10.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_11(Variable vlen_3202, Variable vl_3202) {
	exists(AssignAddExpr target_11 |
		target_11.getLValue().(VariableAccess).getTarget()=vlen_3202
		and target_11.getRValue().(VariableAccess).getTarget()=vl_3202)
}

predicate func_13(Parameter vctxt_3201, Variable vl_3202) {
	exists(AddressOfExpr target_13 |
		target_13.getOperand().(VariableAccess).getTarget()=vl_3202
		and target_13.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xmlCurrentChar")
		and target_13.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_3201)
}

from Function func, Parameter vctxt_3201, Variable vlen_3202, Variable vl_3202
where
func_0(func)
and not func_1(func)
and not func_2(vlen_3202, vl_3202)
and not func_3(vlen_3202, vl_3202)
and not func_4(vctxt_3201, vlen_3202, func)
and func_6(vlen_3202, vl_3202)
and func_8(vctxt_3201)
and func_9(func)
and func_10(vctxt_3201, vlen_3202)
and vctxt_3201.getType().hasName("xmlParserCtxtPtr")
and vlen_3202.getType().hasName("int")
and func_11(vlen_3202, vl_3202)
and vl_3202.getType().hasName("int")
and func_13(vctxt_3201, vl_3202)
and vctxt_3201.getParentScope+() = func
and vlen_3202.getParentScope+() = func
and vl_3202.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
