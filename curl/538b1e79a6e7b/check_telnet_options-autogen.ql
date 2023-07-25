/**
 * @name curl-538b1e79a6e7b-check_telnet_options
 * @id cpp/curl/538b1e79a6e7b/check-telnet-options
 * @description curl-538b1e79a6e7b-lib/telnet.c-check_telnet_options CVE-2023-27533
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vdata_773, ExprStmt target_11, ExprStmt target_12) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("str_is_nonascii")
		and target_0.getArgument(0).(PointerFieldAccess).getTarget().getName()="user"
		and target_0.getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="conn"
		and target_0.getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_773
		and target_11.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_12.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(VariableAccess target_10, Function func) {
	exists(ReturnStmt target_1 |
		target_1.getParent().(IfStmt).getCondition()=target_10
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Variable volen_796, Variable voption_797, Variable varg_798, Variable vsep_799, FunctionCall target_13, FunctionCall target_14, ExprStmt target_15) {
	exists(IfStmt target_2 |
		target_2.getCondition().(VariableAccess).getTarget()=vsep_799
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=volen_796
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vsep_799
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=voption_797
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=varg_798
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PrefixIncrExpr).getOperand().(VariableAccess).getTarget()=vsep_799
		and target_2.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("str_is_nonascii")
		and target_2.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=varg_798
		and target_2.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(ContinueStmt).toString() = "continue;"
		and target_2.getThen().(BlockStmt).getStmt(3).(BlockStmt).getStmt(0).(SwitchStmt).getExpr().(VariableAccess).getTarget()=volen_796
		and target_2.getThen().(BlockStmt).getStmt(3).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(0).(SwitchCase).getExpr().(Literal).getValue()="5"
		and target_2.getThen().(BlockStmt).getStmt(3).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("curl_strnequal")
		and target_2.getThen().(BlockStmt).getStmt(3).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(2).(BreakStmt).toString() = "break;"
		and target_2.getThen().(BlockStmt).getStmt(3).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(3).(SwitchCase).getExpr().(Literal).getValue()="8"
		and target_2.getThen().(BlockStmt).getStmt(3).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(4).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("curl_strnequal")
		and target_2.getThen().(BlockStmt).getStmt(3).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(5).(BreakStmt).toString() = "break;"
		and target_2.getThen().(BlockStmt).getStmt(3).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(6).(SwitchCase).getExpr().(Literal).getValue()="7"
		and target_2.getThen().(BlockStmt).getStmt(3).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(7).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("curl_strnequal")
		and target_2.getThen().(BlockStmt).getStmt(3).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(8).(BreakStmt).toString() = "break;"
		and target_2.getThen().(BlockStmt).getStmt(3).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(9).(SwitchCase).getExpr().(Literal).getValue()="2"
		and target_2.getThen().(BlockStmt).getStmt(3).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(10).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("curl_strnequal")
		and target_2.getThen().(BlockStmt).getStmt(3).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(11).(BreakStmt).toString() = "break;"
		and target_2.getThen().(BlockStmt).getStmt(3).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(12).(SwitchCase).getExpr().(Literal).getValue()="6"
		and target_2.getThen().(BlockStmt).getStmt(3).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(13).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("curl_strnequal")
		and target_2.getThen().(BlockStmt).getStmt(3).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(14).(BreakStmt).toString() = "break;"
		and target_2.getThen().(BlockStmt).getStmt(3).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(15).(SwitchCase).toString() = "default: "
		and target_2.getThen().(BlockStmt).getStmt(3).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(16).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("Curl_failf")
		and target_2.getThen().(BlockStmt).getStmt(3).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(18).(BreakStmt).toString() = "break;"
		and target_2.getThen().(BlockStmt).getStmt(3).(BlockStmt).getStmt(1).(LabelStmt).toString() = "label ...:"
		and target_2.getElse() instanceof BlockStmt
		and target_13.getArgument(0).(VariableAccess).getLocation().isBefore(target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getLocation())
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getLocation().isBefore(target_14.getArgument(0).(VariableAccess).getLocation())
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_15.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

/*predicate func_3(Variable varg_798, VariableAccess target_10, ExprStmt target_16, ExprStmt target_15) {
	exists(IfStmt target_3 |
		target_3.getCondition().(FunctionCall).getTarget().hasName("str_is_nonascii")
		and target_3.getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=varg_798
		and target_3.getThen().(ContinueStmt).toString() = "continue;"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_3
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_10
		and target_16.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_3.getCondition().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_3.getCondition().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_15.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

*/
predicate func_9(Variable vhead_775, Variable vresult_778, Parameter vdata_773, VariableAccess target_10, BlockStmt target_9) {
		target_9.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("Curl_failf")
		and target_9.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata_773
		and target_9.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Syntax error in telnet option: %s"
		and target_9.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="data"
		and target_9.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhead_775
		and target_9.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_778
		and target_9.getParent().(IfStmt).getCondition()=target_10
}

predicate func_10(Variable vsep_799, BlockStmt target_17, VariableAccess target_10) {
		target_10.getTarget()=vsep_799
		and target_10.getParent().(IfStmt).getThen()=target_17
}

predicate func_11(Variable vhead_775, Parameter vdata_773, ExprStmt target_11) {
		target_11.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vhead_775
		and target_11.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="telnet_options"
		and target_11.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_11.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_773
}

predicate func_12(Variable vhead_775, Parameter vdata_773, ExprStmt target_12) {
		target_12.getExpr().(FunctionCall).getTarget().hasName("Curl_failf")
		and target_12.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata_773
		and target_12.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Syntax error in telnet option: %s"
		and target_12.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="data"
		and target_12.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhead_775
}

predicate func_13(Variable voption_797, FunctionCall target_13) {
		target_13.getTarget().hasName("strchr")
		and target_13.getArgument(0).(VariableAccess).getTarget()=voption_797
		and target_13.getArgument(1).(CharLiteral).getValue()="61"
}

predicate func_14(Variable voption_797, FunctionCall target_14) {
		target_14.getTarget().hasName("curl_strnequal")
		and target_14.getArgument(0).(VariableAccess).getTarget()=voption_797
		and target_14.getArgument(1).(StringLiteral).getValue()="TTYPE"
		and target_14.getArgument(2).(Literal).getValue()="5"
}

predicate func_15(Variable varg_798, ExprStmt target_15) {
		target_15.getExpr().(FunctionCall).getTarget().hasName("strncpy")
		and target_15.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="subopt_ttype"
		and target_15.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=varg_798
		and target_15.getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="31"
}

predicate func_16(Variable varg_798, Variable vsep_799, ExprStmt target_16) {
		target_16.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=varg_798
		and target_16.getExpr().(AssignExpr).getRValue().(PrefixIncrExpr).getOperand().(VariableAccess).getTarget()=vsep_799
}

predicate func_17(Variable volen_796, Variable voption_797, Variable varg_798, Variable vsep_799, BlockStmt target_17) {
		target_17.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=volen_796
		and target_17.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vsep_799
		and target_17.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=voption_797
		and target_17.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=varg_798
		and target_17.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PrefixIncrExpr).getOperand().(VariableAccess).getTarget()=vsep_799
}

from Function func, Variable vhead_775, Variable vresult_778, Variable volen_796, Variable voption_797, Variable varg_798, Variable vsep_799, Parameter vdata_773, BlockStmt target_9, VariableAccess target_10, ExprStmt target_11, ExprStmt target_12, FunctionCall target_13, FunctionCall target_14, ExprStmt target_15, ExprStmt target_16, BlockStmt target_17
where
not func_0(vdata_773, target_11, target_12)
and not func_1(target_10, func)
and not func_2(volen_796, voption_797, varg_798, vsep_799, target_13, target_14, target_15)
and func_9(vhead_775, vresult_778, vdata_773, target_10, target_9)
and func_10(vsep_799, target_17, target_10)
and func_11(vhead_775, vdata_773, target_11)
and func_12(vhead_775, vdata_773, target_12)
and func_13(voption_797, target_13)
and func_14(voption_797, target_14)
and func_15(varg_798, target_15)
and func_16(varg_798, vsep_799, target_16)
and func_17(volen_796, voption_797, varg_798, vsep_799, target_17)
and vhead_775.getType().hasName("curl_slist *")
and vresult_778.getType().hasName("CURLcode")
and volen_796.getType().hasName("size_t")
and voption_797.getType().hasName("char *")
and varg_798.getType().hasName("char *")
and vsep_799.getType().hasName("char *")
and vdata_773.getType().hasName("Curl_easy *")
and vhead_775.getParentScope+() = func
and vresult_778.getParentScope+() = func
and volen_796.getParentScope+() = func
and voption_797.getParentScope+() = func
and varg_798.getParentScope+() = func
and vsep_799.getParentScope+() = func
and vdata_773.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
