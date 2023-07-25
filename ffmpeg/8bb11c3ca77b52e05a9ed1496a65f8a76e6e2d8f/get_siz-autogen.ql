/**
 * @name ffmpeg-8bb11c3ca77b52e05a9ed1496a65f8a76e6e2d8f-get_siz
 * @id cpp/ffmpeg/8bb11c3ca77b52e05a9ed1496a65f8a76e6e2d8f/get-siz
 * @description ffmpeg-8bb11c3ca77b52e05a9ed1496a65f8a76e6e2d8f-libavcodec/jpeg2000dec.c-get_siz CVE-2013-7016
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vi_226, Parameter vs_224, BlockStmt target_4, ExprStmt target_5) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand() instanceof NotExpr
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="cdx"
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_226
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="3"
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="cdx"
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_224
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_226
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="4"
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand() instanceof NotExpr
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="cdy"
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_224
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_226
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="3"
		and target_0.getParent().(LogicalOrExpr).getAnOperand() instanceof NotExpr
		and target_0.getParent().(LogicalOrExpr).getAnOperand() instanceof NotExpr
		and target_0.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_4
		and target_5.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation()))
}

predicate func_1(Variable vi_226, Parameter vs_224, BlockStmt target_4) {
	exists(RelationalOperation target_1 |
		 (target_1 instanceof GTExpr or target_1 instanceof LTExpr)
		and target_1.getGreaterOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="cdy"
		and target_1.getGreaterOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_224
		and target_1.getGreaterOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_226
		and target_1.getLesserOperand().(Literal).getValue()="4"
		and target_1.getParent().(LogicalOrExpr).getAnOperand() instanceof NotExpr
		and target_1.getParent().(LogicalOrExpr).getAnOperand() instanceof NotExpr
		and target_1.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_4)
}

predicate func_2(Variable vi_226, Parameter vs_224, BlockStmt target_4, NotExpr target_2) {
		target_2.getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="cdx"
		and target_2.getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_224
		and target_2.getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_226
		and target_2.getParent().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="cdy"
		and target_2.getParent().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_224
		and target_2.getParent().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_226
		and target_2.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_4
}

/*predicate func_3(Variable vi_226, Parameter vs_224, BlockStmt target_4, NotExpr target_3) {
		target_3.getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="cdy"
		and target_3.getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_224
		and target_3.getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_226
		and target_3.getParent().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="cdx"
		and target_3.getParent().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_224
		and target_3.getParent().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_226
		and target_3.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_4
}

*/
predicate func_4(Parameter vs_224, BlockStmt target_4) {
		target_4.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_4.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="avctx"
		and target_4.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_224
		and target_4.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="16"
		and target_4.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Invalid sample seperation\n"
}

predicate func_5(Variable vi_226, Parameter vs_224, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="cdy"
		and target_5.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_224
		and target_5.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_226
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("bytestream2_get_byteu")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="g"
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_224
}

from Function func, Variable vi_226, Parameter vs_224, NotExpr target_2, BlockStmt target_4, ExprStmt target_5
where
not func_0(vi_226, vs_224, target_4, target_5)
and not func_1(vi_226, vs_224, target_4)
and func_2(vi_226, vs_224, target_4, target_2)
and func_4(vs_224, target_4)
and func_5(vi_226, vs_224, target_5)
and vi_226.getType().hasName("int")
and vs_224.getType().hasName("Jpeg2000DecoderContext *")
and vi_226.(LocalVariable).getFunction() = func
and vs_224.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
