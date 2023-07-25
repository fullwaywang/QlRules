/**
 * @name ffmpeg-a1b9004b768bef606ee98d417bceb9392ceb788d-get_cox
 * @id cpp/ffmpeg/a1b9004b768bef606ee98d417bceb9392ceb788d/get-cox
 * @description ffmpeg-a1b9004b768bef606ee98d417bceb9392ceb788d-libavcodec/jpeg2000dec.c-get_cox CVE-2013-7019
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vc_358, Parameter vs_358, ExprStmt target_12, ExprStmt target_13) {
	exists(RelationalOperation target_0 |
		 (target_0 instanceof GEExpr or target_0 instanceof LEExpr)
		and target_0.getLesserOperand().(PointerFieldAccess).getTarget().getName()="nreslevels"
		and target_0.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_358
		and target_0.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="reduction_factor"
		and target_0.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_358
		and target_0.getParent().(IfStmt).getThen()=target_12
		and target_13.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vc_358, Parameter vs_358, RelationalOperation target_11) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("av_log")
		and target_1.getArgument(0).(PointerFieldAccess).getTarget().getName()="avctx"
		and target_1.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_358
		and target_1.getArgument(1).(Literal).getValue()="16"
		and target_1.getArgument(2).(StringLiteral).getValue()="reduction_factor too large for this bitstream, max is %d\n"
		and target_1.getArgument(3).(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="nreslevels"
		and target_1.getArgument(3).(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_358
		and target_1.getArgument(3).(SubExpr).getRightOperand() instanceof Literal
		and target_11.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getArgument(3).(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vc_358, Parameter vs_358, RelationalOperation target_11, ExprStmt target_12, ExprStmt target_9) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="reduction_factor"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_358
		and target_2.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="nreslevels"
		and target_2.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_358
		and target_2.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
		and target_2.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_12.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_9.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

/*predicate func_3(Parameter vs_358, ExprStmt target_9) {
	exists(PointerFieldAccess target_3 |
		target_3.getTarget().getName()="reduction_factor"
		and target_3.getQualifier().(VariableAccess).getTarget()=vs_358
		and target_3.getQualifier().(VariableAccess).getLocation().isBefore(target_9.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

*/
/*predicate func_4(Parameter vc_358, ExprStmt target_12) {
	exists(SubExpr target_4 |
		target_4.getLeftOperand().(PointerFieldAccess).getTarget().getName()="nreslevels"
		and target_4.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_358
		and target_4.getRightOperand().(Literal).getValue()="1"
		and target_4.getParent().(AssignExpr).getRValue() = target_4
		and target_4.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="nreslevels2decode"
		and target_4.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_358
		and target_4.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_12.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

*/
predicate func_5(RelationalOperation target_11, Function func) {
	exists(ReturnStmt target_5 |
		target_5.getExpr().(UnaryMinusExpr).getValue()="-22"
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_5
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
		and target_5.getEnclosingFunction() = func)
}

predicate func_6(Parameter vc_358, Parameter vs_358, ExprStmt target_12, PointerFieldAccess target_6) {
		target_6.getTarget().getName()="nreslevels"
		and target_6.getQualifier().(VariableAccess).getTarget()=vc_358
		and target_6.getParent().(LTExpr).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="reduction_factor"
		and target_6.getParent().(LTExpr).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_358
		and target_6.getParent().(LTExpr).getParent().(IfStmt).getThen()=target_12
}

/*predicate func_7(Parameter vc_358, Parameter vs_358, ExprStmt target_12, PointerFieldAccess target_7) {
		target_7.getTarget().getName()="reduction_factor"
		and target_7.getQualifier().(VariableAccess).getTarget()=vs_358
		and target_7.getParent().(LTExpr).getLesserOperand().(PointerFieldAccess).getTarget().getName()="nreslevels"
		and target_7.getParent().(LTExpr).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_358
		and target_7.getParent().(LTExpr).getParent().(IfStmt).getThen()=target_12
}

*/
predicate func_8(Parameter vc_358, PointerFieldAccess target_8) {
		target_8.getTarget().getName()="nreslevels2decode"
		and target_8.getQualifier().(VariableAccess).getTarget()=vc_358
		and target_8.getParent().(AssignExpr).getLValue() = target_8
		and target_8.getParent().(AssignExpr).getRValue().(Literal).getValue()="1"
}

predicate func_9(Parameter vc_358, Parameter vs_358, RelationalOperation target_11, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="nreslevels2decode"
		and target_9.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_358
		and target_9.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="nreslevels"
		and target_9.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_358
		and target_9.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="reduction_factor"
		and target_9.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_358
		and target_9.getParent().(IfStmt).getCondition()=target_11
}

predicate func_11(Parameter vc_358, Parameter vs_358, ExprStmt target_12, RelationalOperation target_11) {
		 (target_11 instanceof GTExpr or target_11 instanceof LTExpr)
		and target_11.getLesserOperand().(PointerFieldAccess).getTarget().getName()="nreslevels"
		and target_11.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_358
		and target_11.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="reduction_factor"
		and target_11.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_358
		and target_11.getParent().(IfStmt).getThen()=target_12
}

predicate func_12(Parameter vc_358, ExprStmt target_12) {
		target_12.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="nreslevels2decode"
		and target_12.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_358
		and target_12.getExpr().(AssignExpr).getRValue() instanceof Literal
}

predicate func_13(Parameter vc_358, Parameter vs_358, ExprStmt target_13) {
		target_13.getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_13.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="avctx"
		and target_13.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_358
		and target_13.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="16"
		and target_13.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="nreslevels %d is invalid\n"
		and target_13.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="nreslevels"
		and target_13.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_358
}

from Function func, Parameter vc_358, Parameter vs_358, PointerFieldAccess target_6, PointerFieldAccess target_8, ExprStmt target_9, RelationalOperation target_11, ExprStmt target_12, ExprStmt target_13
where
not func_0(vc_358, vs_358, target_12, target_13)
and not func_1(vc_358, vs_358, target_11)
and not func_2(vc_358, vs_358, target_11, target_12, target_9)
and not func_5(target_11, func)
and func_6(vc_358, vs_358, target_12, target_6)
and func_8(vc_358, target_8)
and func_9(vc_358, vs_358, target_11, target_9)
and func_11(vc_358, vs_358, target_12, target_11)
and func_12(vc_358, target_12)
and func_13(vc_358, vs_358, target_13)
and vc_358.getType().hasName("Jpeg2000CodingStyle *")
and vs_358.getType().hasName("Jpeg2000DecoderContext *")
and vc_358.getFunction() = func
and vs_358.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
