/**
 * @name varnish-6da64a47beff44ecdb45c82b033811f2d19819af-http1_dissect_hdrs
 * @id cpp/varnish/6da64a47beff44ecdb45c82b033811f2d19819af/http1-dissect-hdrs
 * @description varnish-6da64a47beff44ecdb45c82b033811f2d19819af-bin/varnishd/http1/cache_http1_proto.c-http1_dissect_hdrs CVE-2019-15892
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, StringLiteral target_0) {
		target_0.getValue()="r < htc->rxbuf_e"
		and not target_0.getValue()="r <= htc->rxbuf_e"
		and target_0.getEnclosingFunction() = func
}

predicate func_2(Variable vi_114, BlockStmt target_16) {
	exists(EqualityOperation target_2 |
		target_2.getAnOperand().(VariableAccess).getTarget()=vi_114
		and target_2.getAnOperand().(Literal).getValue()="0"
		and target_2.getParent().(IfStmt).getThen()=target_16)
}

predicate func_3(Variable vr_113, Variable vi_114, NotExpr target_13) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vr_113
		and target_3.getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getTarget()=vi_114
		and target_13.getOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation()))
}

predicate func_4(Parameter vhtc_110, Variable vr_113, BlockStmt target_16, ExprStmt target_19) {
	exists(RelationalOperation target_4 |
		 (target_4 instanceof GEExpr or target_4 instanceof LEExpr)
		and target_4.getLesserOperand().(VariableAccess).getTarget()=vr_113
		and target_4.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="rxbuf_e"
		and target_4.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhtc_110
		and target_4.getParent().(NotExpr).getOperand() instanceof FunctionCall
		and target_4.getParent().(NotExpr).getParent().(IfStmt).getThen()=target_16
		and target_19.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_4.getLesserOperand().(VariableAccess).getLocation()))
}

predicate func_5(Parameter vhtc_110, Variable vr_113, BreakStmt target_20, NotExpr target_13, RelationalOperation target_15) {
	exists(EqualityOperation target_5 |
		target_5.getAnOperand().(VariableAccess).getTarget()=vr_113
		and target_5.getAnOperand().(PointerFieldAccess).getTarget().getName()="rxbuf_e"
		and target_5.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhtc_110
		and target_5.getParent().(IfStmt).getThen()=target_20
		and target_13.getOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_5.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_15.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_6(Parameter vhtc_110, PointerFieldAccess target_6) {
		target_6.getTarget().getName()="rxbuf_e"
		and target_6.getQualifier().(VariableAccess).getTarget()=vhtc_110
}

predicate func_7(Parameter vhtc_110, PointerFieldAccess target_7) {
		target_7.getTarget().getName()="rxbuf_e"
		and target_7.getQualifier().(VariableAccess).getTarget()=vhtc_110
		and target_7.getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_8(Parameter vhtc_110, Variable vr_113, BreakStmt target_20, PointerFieldAccess target_8) {
		target_8.getTarget().getName()="rxbuf_e"
		and target_8.getQualifier().(VariableAccess).getTarget()=vhtc_110
		and target_8.getParent().(GEExpr).getGreaterOperand().(VariableAccess).getTarget()=vr_113
		and target_8.getParent().(GEExpr).getParent().(IfStmt).getThen()=target_20
}

predicate func_9(Parameter vhtc_110, Variable vr_113, FunctionCall target_9) {
		target_9.getTarget().hasName("vct_iscrlf")
		and target_9.getArgument(0).(VariableAccess).getTarget()=vr_113
		and target_9.getArgument(1).(PointerFieldAccess).getTarget().getName()="rxbuf_e"
		and target_9.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhtc_110
}

predicate func_10(Variable vr_113, VariableAccess target_10) {
		target_10.getTarget()=vr_113
}

predicate func_11(Variable vr_113, VariableAccess target_11) {
		target_11.getTarget()=vr_113
		and target_11.getParent().(AssignExpr).getLValue() = target_11
		and target_11.getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_12(Variable vr_113, VariableAccess target_12) {
		target_12.getTarget()=vr_113
		and target_12.getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_13(Parameter vhtc_110, Variable vr_113, BlockStmt target_22, NotExpr target_13) {
		target_13.getOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vr_113
		and target_13.getOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="rxbuf_e"
		and target_13.getOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhtc_110
		and target_13.getParent().(IfStmt).getThen()=target_22
}

predicate func_14(Parameter vhtc_110, Variable vr_113, AssignExpr target_14) {
		target_14.getLValue().(VariableAccess).getTarget()=vr_113
		and target_14.getRValue().(FunctionCall).getTarget().hasName("vct_skipcrlf")
		and target_14.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vr_113
		and target_14.getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="rxbuf_e"
		and target_14.getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhtc_110
}

predicate func_15(Parameter vhtc_110, Variable vr_113, BreakStmt target_20, RelationalOperation target_15) {
		 (target_15 instanceof GEExpr or target_15 instanceof LEExpr)
		and target_15.getGreaterOperand().(VariableAccess).getTarget()=vr_113
		and target_15.getLesserOperand().(PointerFieldAccess).getTarget().getName()="rxbuf_e"
		and target_15.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhtc_110
		and target_15.getParent().(IfStmt).getThen()=target_20
}

predicate func_16(Variable vr_113, BlockStmt target_16) {
		target_16.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("VSLb")
		and target_16.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="vsl"
		and target_16.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Header has ctrl char 0x%02x"
		and target_16.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vr_113
		and target_16.getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="400"
}

predicate func_19(Variable vr_113, ExprStmt target_19) {
		target_19.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vr_113
}

predicate func_20(BreakStmt target_20) {
		target_20.toString() = "break;"
}

predicate func_22(BlockStmt target_22) {
		target_22.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("VAS_Fail")
		and target_22.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_22.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_22.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
}

from Function func, Parameter vhtc_110, Variable vr_113, Variable vi_114, StringLiteral target_0, PointerFieldAccess target_6, PointerFieldAccess target_7, PointerFieldAccess target_8, FunctionCall target_9, VariableAccess target_10, VariableAccess target_11, VariableAccess target_12, NotExpr target_13, AssignExpr target_14, RelationalOperation target_15, BlockStmt target_16, ExprStmt target_19, BreakStmt target_20, BlockStmt target_22
where
func_0(func, target_0)
and not func_2(vi_114, target_16)
and not func_3(vr_113, vi_114, target_13)
and not func_4(vhtc_110, vr_113, target_16, target_19)
and not func_5(vhtc_110, vr_113, target_20, target_13, target_15)
and func_6(vhtc_110, target_6)
and func_7(vhtc_110, target_7)
and func_8(vhtc_110, vr_113, target_20, target_8)
and func_9(vhtc_110, vr_113, target_9)
and func_10(vr_113, target_10)
and func_11(vr_113, target_11)
and func_12(vr_113, target_12)
and func_13(vhtc_110, vr_113, target_22, target_13)
and func_14(vhtc_110, vr_113, target_14)
and func_15(vhtc_110, vr_113, target_20, target_15)
and func_16(vr_113, target_16)
and func_19(vr_113, target_19)
and func_20(target_20)
and func_22(target_22)
and vhtc_110.getType().hasName("http_conn *")
and vr_113.getType().hasName("char *")
and vi_114.getType().hasName("int")
and vhtc_110.getParentScope+() = func
and vr_113.getParentScope+() = func
and vi_114.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
