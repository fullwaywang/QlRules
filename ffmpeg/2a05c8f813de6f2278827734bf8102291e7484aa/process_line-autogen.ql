/**
 * @name ffmpeg-2a05c8f813de6f2278827734bf8102291e7484aa-process_line
 * @id cpp/ffmpeg/2a05c8f813de6f2278827734bf8102291e7484aa/process-line
 * @description ffmpeg-2a05c8f813de6f2278827734bf8102291e7484aa-libavformat/http.c-process_line CVE-2016-10190
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Variable vs_723, Variable vp_725, LogicalAndExpr target_17, LogicalAndExpr target_18, RelationalOperation target_19, ExprStmt target_20) {
	exists(AssignExpr target_1 |
		target_1.getLValue().(PointerFieldAccess).getTarget().getName()="filesize"
		and target_1.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_723
		and target_1.getRValue().(FunctionCall).getTarget().hasName("strtoull")
		and target_1.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_725
		and target_1.getRValue().(FunctionCall).getArgument(1) instanceof Literal
		and target_1.getRValue().(FunctionCall).getArgument(2) instanceof Literal
		and target_17.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_18.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_19.getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_1.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_1.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_20.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_2(Variable vs_723, LogicalAndExpr target_18, ExprStmt target_21) {
	exists(AssignExpr target_2 |
		target_2.getLValue().(PointerFieldAccess).getTarget().getName()="filesize"
		and target_2.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_723
		and target_2.getRValue().(Literal).getValue()="18446744073709551615"
		and target_18.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_2.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_21.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_3(Variable vs_723, Variable vp_725, AddressOfExpr target_22, RelationalOperation target_23, ExprStmt target_24) {
	exists(AssignExpr target_3 |
		target_3.getLValue().(PointerFieldAccess).getTarget().getName()="icy_metaint"
		and target_3.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_723
		and target_3.getRValue().(FunctionCall).getTarget().hasName("strtoull")
		and target_3.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_725
		and target_3.getRValue().(FunctionCall).getArgument(1) instanceof Literal
		and target_3.getRValue().(FunctionCall).getArgument(2) instanceof Literal
		and target_22.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_3.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_23.getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_24.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getLocation().isBefore(target_3.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_4(Function func, UnaryMinusExpr target_4) {
		target_4.getValue()="-1"
		and target_4.getEnclosingFunction() = func
}

predicate func_5(Variable vs_723, PointerFieldAccess target_5) {
		target_5.getTarget().getName()="filesize"
		and target_5.getQualifier().(VariableAccess).getTarget()=vs_723
		and target_5.getParent().(AssignExpr).getLValue() = target_5
		and target_5.getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_6(Variable vs_723, PointerFieldAccess target_6) {
		target_6.getTarget().getName()="filesize"
		and target_6.getQualifier().(VariableAccess).getTarget()=vs_723
		and target_6.getParent().(AssignExpr).getLValue() = target_6
		and target_6.getParent().(AssignExpr).getRValue() instanceof UnaryMinusExpr
}

predicate func_7(Variable vs_723, PointerFieldAccess target_7) {
		target_7.getTarget().getName()="icy_metaint"
		and target_7.getQualifier().(VariableAccess).getTarget()=vs_723
		and target_7.getParent().(AssignExpr).getLValue() = target_7
		and target_7.getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_8(Variable vp_725, VariableAccess target_8) {
		target_8.getTarget()=vp_725
		and target_8.getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_11(Variable vp_725, VariableAccess target_11) {
		target_11.getTarget()=vp_725
		and target_11.getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_14(Variable vs_723, Variable vp_725, AssignExpr target_14) {
		target_14.getLValue().(PointerFieldAccess).getTarget().getName()="filesize"
		and target_14.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_723
		and target_14.getRValue().(FunctionCall).getTarget().hasName("strtoll")
		and target_14.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_725
		and target_14.getRValue().(FunctionCall).getArgument(1) instanceof Literal
		and target_14.getRValue().(FunctionCall).getArgument(2) instanceof Literal
}

predicate func_15(Variable vs_723, AssignExpr target_15) {
		target_15.getLValue().(PointerFieldAccess).getTarget().getName()="filesize"
		and target_15.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_723
		and target_15.getRValue().(UnaryMinusExpr).getValue()="-1"
}

predicate func_16(Variable vs_723, Variable vp_725, AssignExpr target_16) {
		target_16.getLValue().(PointerFieldAccess).getTarget().getName()="icy_metaint"
		and target_16.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_723
		and target_16.getRValue().(FunctionCall).getTarget().hasName("strtoll")
		and target_16.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_725
		and target_16.getRValue().(FunctionCall).getArgument(1) instanceof Literal
		and target_16.getRValue().(FunctionCall).getArgument(2) instanceof Literal
}

predicate func_17(Variable vs_723, LogicalAndExpr target_17) {
		target_17.getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("av_strcasecmp")
		and target_17.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Content-Length"
		and target_17.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="filesize"
		and target_17.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_723
		and target_17.getAnOperand().(EqualityOperation).getAnOperand() instanceof UnaryMinusExpr
}

predicate func_18(Variable vs_723, Variable vp_725, LogicalAndExpr target_18) {
		target_18.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("av_strcasecmp")
		and target_18.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Accept-Ranges"
		and target_18.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("strncmp")
		and target_18.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_725
		and target_18.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="bytes"
		and target_18.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(Literal).getValue()="5"
		and target_18.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="seekable"
		and target_18.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_723
		and target_18.getAnOperand().(EqualityOperation).getAnOperand().(UnaryMinusExpr).getValue()="-1"
}

predicate func_19(Variable vs_723, Variable vp_725, RelationalOperation target_19) {
		 (target_19 instanceof GTExpr or target_19 instanceof LTExpr)
		and target_19.getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("parse_location")
		and target_19.getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_723
		and target_19.getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vp_725
		and target_19.getGreaterOperand().(Literal).getValue()="0"
}

predicate func_20(Variable vp_725, ExprStmt target_20) {
		target_20.getExpr().(FunctionCall).getTarget().hasName("parse_content_range")
		and target_20.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vp_725
}

predicate func_21(Variable vs_723, ExprStmt target_21) {
		target_21.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="chunksize"
		and target_21.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_723
		and target_21.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_22(Variable vs_723, AddressOfExpr target_22) {
		target_22.getOperand().(PointerFieldAccess).getTarget().getName()="cookie_dict"
		and target_22.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_723
}

predicate func_23(Variable vs_723, Variable vp_725, RelationalOperation target_23) {
		 (target_23 instanceof GTExpr or target_23 instanceof LTExpr)
		and target_23.getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("parse_icy")
		and target_23.getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_723
		and target_23.getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vp_725
		and target_23.getGreaterOperand().(Literal).getValue()="0"
}

predicate func_24(Variable vp_725, ExprStmt target_24) {
		target_24.getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_24.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="24"
		and target_24.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Unable to parse '%s'\n"
		and target_24.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vp_725
}

from Function func, Variable vs_723, Variable vp_725, UnaryMinusExpr target_4, PointerFieldAccess target_5, PointerFieldAccess target_6, PointerFieldAccess target_7, VariableAccess target_8, VariableAccess target_11, AssignExpr target_14, AssignExpr target_15, AssignExpr target_16, LogicalAndExpr target_17, LogicalAndExpr target_18, RelationalOperation target_19, ExprStmt target_20, ExprStmt target_21, AddressOfExpr target_22, RelationalOperation target_23, ExprStmt target_24
where
not func_1(vs_723, vp_725, target_17, target_18, target_19, target_20)
and not func_2(vs_723, target_18, target_21)
and not func_3(vs_723, vp_725, target_22, target_23, target_24)
and func_4(func, target_4)
and func_5(vs_723, target_5)
and func_6(vs_723, target_6)
and func_7(vs_723, target_7)
and func_8(vp_725, target_8)
and func_11(vp_725, target_11)
and func_14(vs_723, vp_725, target_14)
and func_15(vs_723, target_15)
and func_16(vs_723, vp_725, target_16)
and func_17(vs_723, target_17)
and func_18(vs_723, vp_725, target_18)
and func_19(vs_723, vp_725, target_19)
and func_20(vp_725, target_20)
and func_21(vs_723, target_21)
and func_22(vs_723, target_22)
and func_23(vs_723, vp_725, target_23)
and func_24(vp_725, target_24)
and vs_723.getType().hasName("HTTPContext *")
and vp_725.getType().hasName("char *")
and vs_723.getParentScope+() = func
and vp_725.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
