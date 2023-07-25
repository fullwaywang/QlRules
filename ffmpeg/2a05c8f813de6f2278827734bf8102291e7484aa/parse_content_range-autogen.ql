/**
 * @name ffmpeg-2a05c8f813de6f2278827734bf8102291e7484aa-parse_content_range
 * @id cpp/ffmpeg/2a05c8f813de6f2278827734bf8102291e7484aa/parse-content-range
 * @description ffmpeg-2a05c8f813de6f2278827734bf8102291e7484aa-libavformat/http.c-parse_content_range CVE-2016-10190
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vp_612, Variable vs_614, ExprStmt target_12, LogicalAndExpr target_13) {
	exists(AssignExpr target_0 |
		target_0.getLValue().(PointerFieldAccess).getTarget().getName()="off"
		and target_0.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_614
		and target_0.getRValue().(FunctionCall).getTarget().hasName("strtoull")
		and target_0.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_612
		and target_0.getRValue().(FunctionCall).getArgument(1) instanceof Literal
		and target_0.getRValue().(FunctionCall).getArgument(2) instanceof Literal
		and target_12.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_13.getAnOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Variable vs_614, LogicalAndExpr target_16) {
	exists(AssignExpr target_1 |
		target_1.getLValue().(PointerFieldAccess).getTarget().getName()="filesize"
		and target_1.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_614
		and target_1.getRValue().(FunctionCall).getTarget().hasName("strtoull")
		and target_1.getRValue().(FunctionCall).getArgument(0) instanceof PointerArithmeticOperation
		and target_1.getRValue().(FunctionCall).getArgument(1) instanceof Literal
		and target_1.getRValue().(FunctionCall).getArgument(2) instanceof Literal
		and target_1.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_16.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Variable vslash_615, PointerArithmeticOperation target_2) {
		target_2.getAnOperand().(VariableAccess).getTarget()=vslash_615
		and target_2.getAnOperand().(Literal).getValue()="1"
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_3(Variable vs_614, PointerFieldAccess target_3) {
		target_3.getTarget().getName()="off"
		and target_3.getQualifier().(VariableAccess).getTarget()=vs_614
		and target_3.getParent().(AssignExpr).getLValue() = target_3
		and target_3.getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_4(Variable vs_614, PointerFieldAccess target_4) {
		target_4.getTarget().getName()="filesize"
		and target_4.getQualifier().(VariableAccess).getTarget()=vs_614
		and target_4.getParent().(AssignExpr).getLValue() = target_4
		and target_4.getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_5(Parameter vp_612, VariableAccess target_5) {
		target_5.getTarget()=vp_612
		and target_5.getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_10(Parameter vp_612, Variable vs_614, AssignExpr target_10) {
		target_10.getLValue().(PointerFieldAccess).getTarget().getName()="off"
		and target_10.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_614
		and target_10.getRValue().(FunctionCall).getTarget().hasName("strtoll")
		and target_10.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_612
		and target_10.getRValue().(FunctionCall).getArgument(1) instanceof Literal
		and target_10.getRValue().(FunctionCall).getArgument(2) instanceof Literal
}

predicate func_11(Variable vs_614, AssignExpr target_11) {
		target_11.getLValue().(PointerFieldAccess).getTarget().getName()="filesize"
		and target_11.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_614
		and target_11.getRValue().(FunctionCall).getTarget().hasName("strtoll")
		and target_11.getRValue().(FunctionCall).getArgument(0) instanceof PointerArithmeticOperation
		and target_11.getRValue().(FunctionCall).getArgument(1) instanceof Literal
		and target_11.getRValue().(FunctionCall).getArgument(2) instanceof Literal
}

predicate func_12(Parameter vp_612, ExprStmt target_12) {
		target_12.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vp_612
		and target_12.getExpr().(AssignPointerAddExpr).getRValue().(Literal).getValue()="6"
}

predicate func_13(Parameter vp_612, Variable vslash_615, LogicalAndExpr target_13) {
		target_13.getAnOperand().(AssignExpr).getLValue().(VariableAccess).getTarget()=vslash_615
		and target_13.getAnOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("strchr")
		and target_13.getAnOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_612
		and target_13.getAnOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(CharLiteral).getValue()="47"
		and target_13.getAnOperand().(RelationalOperation).getGreaterOperand().(FunctionCall).getTarget().hasName("strlen")
		and target_13.getAnOperand().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vslash_615
		and target_13.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
}

predicate func_16(Variable vs_614, LogicalAndExpr target_16) {
		target_16.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="seekable"
		and target_16.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_614
		and target_16.getAnOperand().(EqualityOperation).getAnOperand().(UnaryMinusExpr).getValue()="-1"
		and target_16.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="is_akamai"
		and target_16.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_614
		and target_16.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="filesize"
		and target_16.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_614
		and target_16.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="2147483647"
}

from Function func, Parameter vp_612, Variable vs_614, Variable vslash_615, PointerArithmeticOperation target_2, PointerFieldAccess target_3, PointerFieldAccess target_4, VariableAccess target_5, AssignExpr target_10, AssignExpr target_11, ExprStmt target_12, LogicalAndExpr target_13, LogicalAndExpr target_16
where
not func_0(vp_612, vs_614, target_12, target_13)
and not func_1(vs_614, target_16)
and func_2(vslash_615, target_2)
and func_3(vs_614, target_3)
and func_4(vs_614, target_4)
and func_5(vp_612, target_5)
and func_10(vp_612, vs_614, target_10)
and func_11(vs_614, target_11)
and func_12(vp_612, target_12)
and func_13(vp_612, vslash_615, target_13)
and func_16(vs_614, target_16)
and vp_612.getType().hasName("const char *")
and vs_614.getType().hasName("HTTPContext *")
and vslash_615.getType().hasName("const char *")
and vp_612.getParentScope+() = func
and vs_614.getParentScope+() = func
and vslash_615.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
