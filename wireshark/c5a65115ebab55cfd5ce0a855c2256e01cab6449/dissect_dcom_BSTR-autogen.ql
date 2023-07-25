/**
 * @name wireshark-c5a65115ebab55cfd5ce0a855c2256e01cab6449-dissect_dcom_BSTR
 * @id cpp/wireshark/c5a65115ebab55cfd5ce0a855c2256e01cab6449/dissect-dcom-BSTR
 * @description wireshark-c5a65115ebab55cfd5ce0a855c2256e01cab6449-epan/dissectors/packet-dcom.c-dissect_dcom_BSTR CVE-2018-19626
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vpszStr_1714, RelationalOperation target_2, ExprStmt target_3) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vpszStr_1714
		and target_0.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_0.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_0.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getLocation()))
}

predicate func_1(Parameter voffset_1712, RelationalOperation target_2, ReturnStmt target_1) {
		target_1.getExpr().(VariableAccess).getTarget()=voffset_1712
		and target_1.getParent().(IfStmt).getCondition()=target_2
}

predicate func_2(Parameter voffset_1712, RelationalOperation target_2) {
		 (target_2 instanceof GTExpr or target_2 instanceof LTExpr)
		and target_2.getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=voffset_1712
		and target_2.getGreaterOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(Literal).getValue()="2"
		and target_2.getLesserOperand().(Literal).getValue()="2147483647"
}

predicate func_3(Parameter voffset_1712, Parameter vpszStr_1714, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=voffset_1712
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("dcom_tvb_get_nwstringz0")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=voffset_1712
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(MulExpr).getRightOperand().(Literal).getValue()="2"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vpszStr_1714
}

from Function func, Parameter voffset_1712, Parameter vpszStr_1714, ReturnStmt target_1, RelationalOperation target_2, ExprStmt target_3
where
not func_0(vpszStr_1714, target_2, target_3)
and func_1(voffset_1712, target_2, target_1)
and func_2(voffset_1712, target_2)
and func_3(voffset_1712, vpszStr_1714, target_3)
and voffset_1712.getType().hasName("gint")
and vpszStr_1714.getType().hasName("gchar *")
and voffset_1712.getParentScope+() = func
and vpszStr_1714.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
