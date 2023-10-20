/**
 * @name git-7360767e8dfc1895a932324079f7d45d7791d39f-read_attr_from_file
 * @id cpp/git/7360767e8dfc1895a932324079f7d45d7791d39f/read-attr-from-file
 * @description git-7360767e8dfc1895a932324079f7d45d7791d39f-attr.c-read_attr_from_file CVE-2022-41953
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vbuf_1_707, Initializer target_0) {
		target_0.getExpr().(VariableAccess).getTarget()=vbuf_1_707
}

predicate func_1(Variable vbufp_723, ExprStmt target_26, FunctionCall target_1) {
		target_1.getTarget().hasName("skip_utf8_bom")
		and not target_1.getTarget().hasName("fclose")
		and target_1.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vbufp_723
		and target_1.getArgument(1).(FunctionCall).getTarget().hasName("strlen")
		and target_1.getArgument(1).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbufp_723
		and target_1.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getLocation().isBefore(target_26.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
}

predicate func_5(Parameter vpath_702, Variable vfd_704, ExprStmt target_27, ExprStmt target_28, Function func) {
	exists(IfStmt target_5 |
		target_5.getCondition().(FunctionCall).getTarget().hasName("fstat")
		and target_5.getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfd_704
		and target_5.getCondition().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("stat")
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("warning_errno")
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("_")
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(StringLiteral).getValue()="cannot fstat gitattributes file '%s'"
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpath_702
		and target_5.getThen().(BlockStmt).getStmt(1) instanceof ExprStmt
		and target_5.getThen().(BlockStmt).getStmt(2).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_5 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_5)
		and target_27.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_28.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_5.getCondition().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_6(ExprStmt target_29, Function func) {
	exists(RelationalOperation target_6 |
		 (target_6 instanceof GEExpr or target_6 instanceof LEExpr)
		and target_6.getGreaterOperand().(ValueFieldAccess).getTarget().getName()="st_size"
		and target_6.getGreaterOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("stat")
		and target_6.getLesserOperand().(MulExpr).getValue()="104857600"
		and target_6.getParent().(IfStmt).getThen()=target_29
		and target_6.getEnclosingFunction() = func)
}

predicate func_7(Parameter vpath_702, NotExpr target_18, ExprStmt target_26) {
	exists(ExprStmt target_7 |
		target_7.getExpr().(FunctionCall).getTarget().hasName("warning")
		and target_7.getExpr().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("_")
		and target_7.getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(StringLiteral).getValue()="ignoring overly large gitattributes file '%s'"
		and target_7.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpath_702
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_7
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_18
		and target_7.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_26.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation()))
}

predicate func_8(Variable vfp_705, NotExpr target_18, ExprStmt target_17) {
	exists(ExprStmt target_8 |
		target_8.getExpr().(FunctionCall).getTarget().hasName("fclose")
		and target_8.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfp_705
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_8
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_18
		and target_8.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_17.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_9(NotExpr target_18, Function func) {
	exists(ReturnStmt target_9 |
		target_9.getExpr().(Literal).getValue()="0"
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_9
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_18
		and target_9.getEnclosingFunction() = func)
}

predicate func_10(Variable vfp_705, Variable vbuf_1_707, ExprStmt target_28, FunctionCall target_21) {
	exists(EqualityOperation target_10 |
		target_10.getAnOperand().(FunctionCall).getTarget().hasName("strbuf_getline")
		and target_10.getAnOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vbuf_1_707
		and target_10.getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vfp_705
		and target_10.getAnOperand().(UnaryMinusExpr).getValue()="-1"
		and target_28.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_10.getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_10.getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_21.getArgument(2).(VariableAccess).getLocation()))
}

predicate func_11(Variable vbuf_1_707) {
	exists(IfStmt target_11 |
		target_11.getCondition().(LogicalAndExpr).getAnOperand() instanceof NotExpr
		and target_11.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("starts_with")
		and target_11.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="buf"
		and target_11.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_1_707
		and target_11.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("const char[]")
		and target_11.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("strbuf_remove")
		and target_11.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vbuf_1_707
		and target_11.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_11.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(FunctionCall).getTarget().hasName("strlen")
		and target_11.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("const char[]"))
}

/*predicate func_12(Variable vbuf_1_707) {
	exists(FunctionCall target_12 |
		target_12.getTarget().hasName("strbuf_remove")
		and target_12.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vbuf_1_707
		and target_12.getArgument(1).(Literal).getValue()="0"
		and target_12.getArgument(2).(FunctionCall).getTarget().hasName("strlen")
		and target_12.getArgument(2).(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("const char[]"))
}

*/
predicate func_14(Variable vbuf_1_707) {
	exists(ValueFieldAccess target_14 |
		target_14.getTarget().getName()="buf"
		and target_14.getQualifier().(VariableAccess).getTarget()=vbuf_1_707)
}

predicate func_15(Variable vfp_705, ExprStmt target_17, Function func) {
	exists(ExprStmt target_15 |
		target_15.getExpr().(FunctionCall).getTarget().hasName("fclose")
		and target_15.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfp_705
		and (func.getEntryPoint().(BlockStmt).getStmt(13)=target_15 or func.getEntryPoint().(BlockStmt).getStmt(13).getFollowingStmt()=target_15)
		and target_17.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_15.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_16(Variable vbuf_1_707, Function func) {
	exists(ExprStmt target_16 |
		target_16.getExpr().(FunctionCall).getTarget().hasName("strbuf_release")
		and target_16.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vbuf_1_707
		and (func.getEntryPoint().(BlockStmt).getStmt(14)=target_16 or func.getEntryPoint().(BlockStmt).getStmt(14).getFollowingStmt()=target_16))
}

predicate func_17(Variable vfp_705, Function func, ExprStmt target_17) {
		target_17.getExpr().(FunctionCall).getTarget().hasName("fclose")
		and target_17.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfp_705
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_17
}

predicate func_18(Variable vlineno_708, ExprStmt target_29, NotExpr target_18) {
		target_18.getOperand().(VariableAccess).getTarget()=vlineno_708
		and target_18.getParent().(IfStmt).getThen()=target_29
}

predicate func_19(Variable vfp_705, Variable vbuf_1_707, VariableAccess target_19) {
		target_19.getTarget()=vfp_705
		and target_19.getParent().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuf_1_707
		and target_19.getParent().(FunctionCall).getArgument(1) instanceof SizeofExprOperator
}

predicate func_21(Variable vfp_705, Variable vbuf_1_707, FunctionCall target_21) {
		target_21.getTarget().hasName("fgets")
		and target_21.getArgument(0).(VariableAccess).getTarget()=vbuf_1_707
		and target_21.getArgument(1).(SizeofExprOperator).getValue()="2048"
		and target_21.getArgument(2).(VariableAccess).getTarget()=vfp_705
}

predicate func_23(Variable vbufp_723, VariableAccess target_23) {
		target_23.getTarget()=vbufp_723
}

predicate func_24(Variable vbufp_723, ExprStmt target_26, VariableAccess target_24) {
		target_24.getTarget()=vbufp_723
		and target_24.getParent().(FunctionCall).getParent().(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("strlen")
		and target_24.getLocation().isBefore(target_26.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
}

predicate func_25(Parameter vpath_702, Variable vlineno_708, Variable vbufp_723, NotExpr target_18, FunctionCall target_31, VariableAccess target_25) {
		target_25.getTarget()=vbufp_723
		and target_25.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("handle_attr_line")
		and target_25.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vpath_702
		and target_25.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PrefixIncrExpr).getOperand().(VariableAccess).getTarget()=vlineno_708
		and target_18.getOperand().(VariableAccess).getLocation().isBefore(target_25.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PrefixIncrExpr).getOperand().(VariableAccess).getLocation())
		and target_31.getArgument(0).(VariableAccess).getLocation().isBefore(target_25.getLocation())
}

predicate func_26(Parameter vpath_702, Variable vlineno_708, Variable vbufp_723, ExprStmt target_26) {
		target_26.getExpr().(FunctionCall).getTarget().hasName("handle_attr_line")
		and target_26.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbufp_723
		and target_26.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vpath_702
		and target_26.getExpr().(FunctionCall).getArgument(3).(PrefixIncrExpr).getOperand().(VariableAccess).getTarget()=vlineno_708
}

predicate func_27(Parameter vpath_702, ExprStmt target_27) {
		target_27.getExpr().(FunctionCall).getTarget().hasName("warn_on_fopen_errors")
		and target_27.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpath_702
}

predicate func_28(Variable vfd_704, Variable vfp_705, ExprStmt target_28) {
		target_28.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vfp_705
		and target_28.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xfdopen")
		and target_28.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfd_704
		and target_28.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(StringLiteral).getValue()="r"
}

predicate func_29(ExprStmt target_29) {
		target_29.getExpr() instanceof FunctionCall
}

predicate func_31(Variable vbufp_723, FunctionCall target_31) {
		target_31.getTarget().hasName("strlen")
		and target_31.getArgument(0).(VariableAccess).getTarget()=vbufp_723
}

from Function func, Parameter vpath_702, Variable vfd_704, Variable vfp_705, Variable vbuf_1_707, Variable vlineno_708, Variable vbufp_723, Initializer target_0, FunctionCall target_1, ExprStmt target_17, NotExpr target_18, VariableAccess target_19, FunctionCall target_21, VariableAccess target_23, VariableAccess target_24, VariableAccess target_25, ExprStmt target_26, ExprStmt target_27, ExprStmt target_28, ExprStmt target_29, FunctionCall target_31
where
func_0(vbuf_1_707, target_0)
and func_1(vbufp_723, target_26, target_1)
and not func_5(vpath_702, vfd_704, target_27, target_28, func)
and not func_6(target_29, func)
and not func_7(vpath_702, target_18, target_26)
and not func_8(vfp_705, target_18, target_17)
and not func_9(target_18, func)
and not func_10(vfp_705, vbuf_1_707, target_28, target_21)
and not func_11(vbuf_1_707)
and not func_14(vbuf_1_707)
and not func_15(vfp_705, target_17, func)
and not func_16(vbuf_1_707, func)
and func_17(vfp_705, func, target_17)
and func_18(vlineno_708, target_29, target_18)
and func_19(vfp_705, vbuf_1_707, target_19)
and func_21(vfp_705, vbuf_1_707, target_21)
and func_23(vbufp_723, target_23)
and func_24(vbufp_723, target_26, target_24)
and func_25(vpath_702, vlineno_708, vbufp_723, target_18, target_31, target_25)
and func_26(vpath_702, vlineno_708, vbufp_723, target_26)
and func_27(vpath_702, target_27)
and func_28(vfd_704, vfp_705, target_28)
and func_29(target_29)
and func_31(vbufp_723, target_31)
and vpath_702.getType().hasName("const char *")
and vfd_704.getType().hasName("int")
and vfp_705.getType().hasName("FILE *")
and vbuf_1_707.getType().hasName("char[2048]")
and vlineno_708.getType().hasName("int")
and vbufp_723.getType().hasName("char *")
and vpath_702.getParentScope+() = func
and vfd_704.getParentScope+() = func
and vfp_705.getParentScope+() = func
and vbuf_1_707.getParentScope+() = func
and vlineno_708.getParentScope+() = func
and vbufp_723.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
