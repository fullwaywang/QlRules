/**
 * @name wireshark-d443be449a52f95df5754adc39e1f3472fec2f03-parse_VariantColVector
 * @id cpp/wireshark/d443be449a52f95df5754adc39e1f3472fec2f03/parse-VariantColVector
 * @description wireshark-d443be449a52f95df5754adc39e1f3472fec2f03-epan/dissectors/packet-mswsp.c-parse_VariantColVector CVE-2018-18227
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, DeclStmt target_0) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_0
}

predicate func_1(Variable vvt_list_type_5267, Function func, ExprStmt target_1) {
		target_1.getExpr().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vvt_list_type_5267
		and target_1.getExpr().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand() instanceof Literal
		and target_1.getExpr().(ConditionalExpr).getThen() instanceof Literal
		and target_1.getExpr().(ConditionalExpr).getElse().(FunctionCall).getTarget().hasName("proto_report_dissector_bug")
		and target_1.getExpr().(ConditionalExpr).getElse().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("wmem_strdup_printf")
		and target_1.getExpr().(ConditionalExpr).getElse().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("wmem_packet_scope")
		and target_1.getExpr().(ConditionalExpr).getElse().(FunctionCall).getArgument(0).(FunctionCall).getArgument(1).(StringLiteral).getValue()="%s:%u: failed assertion \"%s\""
		and target_1.getExpr().(ConditionalExpr).getElse().(FunctionCall).getArgument(0).(FunctionCall).getArgument(2) instanceof StringLiteral
		and target_1.getExpr().(ConditionalExpr).getElse().(FunctionCall).getArgument(0).(FunctionCall).getArgument(3) instanceof Literal
		and target_1.getExpr().(ConditionalExpr).getElse().(FunctionCall).getArgument(0).(FunctionCall).getArgument(4).(StringLiteral).getValue()="vt_list_type != ((void *)0)"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1
}

from Function func, Variable vvt_list_type_5267, DeclStmt target_0, ExprStmt target_1
where
func_0(func, target_0)
and func_1(vvt_list_type_5267, func, target_1)
and vvt_list_type_5267.getType().hasName("vtype_data *")
and vvt_list_type_5267.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
