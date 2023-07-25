/**
 * @name varnish-1cb778f6f69737109e8c070a74b8e95b78f46d13-http_rxchunk
 * @id cpp/varnish/1cb778f6f69737109e8c070a74b8e95b78f46d13/http-rxchunk
 * @description varnish-1cb778f6f69737109e8c070a74b8e95b78f46d13-bin/varnishtest/vtc_http.c-http_rxchunk CVE-2019-15892
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vold_544, Parameter vhp_542, ExprStmt target_3, RelationalOperation target_4, ExprStmt target_5) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("vct_iscrlf")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vold_544
		and target_0.getArgument(1).(PointerFieldAccess).getTarget().getName()="rx_e"
		and target_0.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhp_542
		and target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getArgument(0).(VariableAccess).getLocation())
		and target_4.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vold_544, VariableAccess target_1) {
		target_1.getTarget()=vold_544
		and target_1.getParent().(ArrayExpr).getArrayOffset() instanceof Literal
}

predicate func_2(Variable vold_544, BlockStmt target_6, LogicalOrExpr target_2) {
		target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vold_544
		and target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="13"
		and target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vold_544
		and target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="10"
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vold_544
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="10"
		and target_2.getParent().(NotExpr).getParent().(IfStmt).getThen()=target_6
}

predicate func_3(Variable vold_544, Parameter vhp_542, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vold_544
		and target_3.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="rx_p"
		and target_3.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhp_542
}

predicate func_4(Parameter vhp_542, RelationalOperation target_4) {
		 (target_4 instanceof GTExpr or target_4 instanceof LTExpr)
		and target_4.getLesserOperand().(FunctionCall).getTarget().hasName("http_rxchar")
		and target_4.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vhp_542
		and target_4.getLesserOperand().(FunctionCall).getArgument(1).(Literal).getValue()="2"
		and target_4.getLesserOperand().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_4.getGreaterOperand().(Literal).getValue()="0"
}

predicate func_5(Parameter vhp_542, ExprStmt target_5) {
		target_5.getExpr().(FunctionCall).getTarget().hasName("vtc_log")
		and target_5.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="vl"
		and target_5.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhp_542
		and target_5.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="fatal"
		and target_5.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhp_542
		and target_5.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Chunklen without CRLF"
}

predicate func_6(Parameter vhp_542, BlockStmt target_6) {
		target_6.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("vtc_log")
		and target_6.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="vl"
		and target_6.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhp_542
		and target_6.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="fatal"
		and target_6.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhp_542
		and target_6.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Chunklen without CRLF"
}

from Function func, Variable vold_544, Parameter vhp_542, VariableAccess target_1, LogicalOrExpr target_2, ExprStmt target_3, RelationalOperation target_4, ExprStmt target_5, BlockStmt target_6
where
not func_0(vold_544, vhp_542, target_3, target_4, target_5)
and func_1(vold_544, target_1)
and func_2(vold_544, target_6, target_2)
and func_3(vold_544, vhp_542, target_3)
and func_4(vhp_542, target_4)
and func_5(vhp_542, target_5)
and func_6(vhp_542, target_6)
and vold_544.getType().hasName("char *")
and vhp_542.getType().hasName("http *")
and vold_544.getParentScope+() = func
and vhp_542.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
