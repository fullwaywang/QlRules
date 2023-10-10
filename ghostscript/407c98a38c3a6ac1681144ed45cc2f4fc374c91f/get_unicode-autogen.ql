/**
 * @name ghostscript-407c98a38c3a6ac1681144ed45cc2f4fc374c91f-get_unicode
 * @id cpp/ghostscript/407c98a38c3a6ac1681144ed45cc2f4fc374c91f/get-unicode
 * @description ghostscript-407c98a38c3a6ac1681144ed45cc2f4fc374c91f-devices/vector/gdevtxtw.c-get_unicode CVE-2020-16307
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vglyph_1686, EqualityOperation target_4, ExprStmt target_5, ExprStmt target_1) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vglyph_1686
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="2147483647"
		and target_0.getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_0.getThen().(BlockStmt).getStmt(1) instanceof IfStmt
		and target_0.getThen().(BlockStmt).getStmt(2) instanceof IfStmt
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
		and target_5.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_1.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vfont_1686, Parameter vglyph_1686, Variable vcode_1688, Variable vgnstr_1689, EqualityOperation target_4, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcode_1688
		and target_1.getExpr().(AssignExpr).getRValue().(VariableCall).getExpr().(ValueFieldAccess).getTarget().getName()="glyph_name"
		and target_1.getExpr().(AssignExpr).getRValue().(VariableCall).getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="procs"
		and target_1.getExpr().(AssignExpr).getRValue().(VariableCall).getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfont_1686
		and target_1.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vfont_1686
		and target_1.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(1).(VariableAccess).getTarget()=vglyph_1686
		and target_1.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vgnstr_1689
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
}

predicate func_2(Variable vcode_1688, Variable vgnstr_1689, EqualityOperation target_4, IfStmt target_2) {
		target_2.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vcode_1688
		and target_2.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_2.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="size"
		and target_2.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vgnstr_1689
		and target_2.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="7"
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("memcmp")
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="data"
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vgnstr_1689
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="uni"
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(Literal).getValue()="3"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
}

predicate func_3(Variable vlength_1692, Variable vsentry_1712, Variable vdentry_1713, Variable vtentry_1714, Variable vqentry_1715, EqualityOperation target_4, IfStmt target_3) {
		target_3.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vlength_1692
		and target_3.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_3.getThen().(BlockStmt).getStmt(4).(BlockStmt).getStmt(0).(WhileStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="Glyph"
		and target_3.getThen().(BlockStmt).getStmt(4).(BlockStmt).getStmt(0).(WhileStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsentry_1712
		and target_3.getThen().(BlockStmt).getStmt(4).(BlockStmt).getStmt(0).(WhileStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_3.getThen().(BlockStmt).getStmt(5).(BlockStmt).getStmt(0).(WhileStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="Glyph"
		and target_3.getThen().(BlockStmt).getStmt(5).(BlockStmt).getStmt(0).(WhileStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdentry_1713
		and target_3.getThen().(BlockStmt).getStmt(5).(BlockStmt).getStmt(0).(WhileStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_3.getThen().(BlockStmt).getStmt(6).(BlockStmt).getStmt(0).(WhileStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="Glyph"
		and target_3.getThen().(BlockStmt).getStmt(6).(BlockStmt).getStmt(0).(WhileStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtentry_1714
		and target_3.getThen().(BlockStmt).getStmt(6).(BlockStmt).getStmt(0).(WhileStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_3.getThen().(BlockStmt).getStmt(7).(BlockStmt).getStmt(0).(WhileStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="Glyph"
		and target_3.getThen().(BlockStmt).getStmt(7).(BlockStmt).getStmt(0).(WhileStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vqentry_1715
		and target_3.getThen().(BlockStmt).getStmt(7).(BlockStmt).getStmt(0).(WhileStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
}

predicate func_4(Variable vlength_1692, EqualityOperation target_4) {
		target_4.getAnOperand().(VariableAccess).getTarget()=vlength_1692
		and target_4.getAnOperand().(Literal).getValue()="0"
}

predicate func_5(Variable vlength_1692, Parameter vfont_1686, Parameter vglyph_1686, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlength_1692
		and target_5.getExpr().(AssignExpr).getRValue().(VariableCall).getExpr().(ValueFieldAccess).getTarget().getName()="decode_glyph"
		and target_5.getExpr().(AssignExpr).getRValue().(VariableCall).getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="procs"
		and target_5.getExpr().(AssignExpr).getRValue().(VariableCall).getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfont_1686
		and target_5.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vfont_1686
		and target_5.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(1).(VariableAccess).getTarget()=vglyph_1686
		and target_5.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("gs_char")
		and target_5.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(3).(Literal).getValue()="0"
		and target_5.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(4).(Literal).getValue()="0"
}

from Function func, Variable vlength_1692, Variable vsentry_1712, Variable vdentry_1713, Variable vtentry_1714, Variable vqentry_1715, Parameter vfont_1686, Parameter vglyph_1686, Variable vcode_1688, Variable vgnstr_1689, ExprStmt target_1, IfStmt target_2, IfStmt target_3, EqualityOperation target_4, ExprStmt target_5
where
not func_0(vglyph_1686, target_4, target_5, target_1)
and func_1(vfont_1686, vglyph_1686, vcode_1688, vgnstr_1689, target_4, target_1)
and func_2(vcode_1688, vgnstr_1689, target_4, target_2)
and func_3(vlength_1692, vsentry_1712, vdentry_1713, vtentry_1714, vqentry_1715, target_4, target_3)
and func_4(vlength_1692, target_4)
and func_5(vlength_1692, vfont_1686, vglyph_1686, target_5)
and vlength_1692.getType().hasName("int")
and vsentry_1712.getType().hasName("single_glyph_list_t *")
and vdentry_1713.getType().hasName("double_glyph_list_t *")
and vtentry_1714.getType().hasName("treble_glyph_list_t *")
and vqentry_1715.getType().hasName("quad_glyph_list_t *")
and vfont_1686.getType().hasName("gs_font *")
and vglyph_1686.getType().hasName("gs_glyph")
and vcode_1688.getType().hasName("int")
and vgnstr_1689.getType().hasName("gs_const_string")
and vlength_1692.(LocalVariable).getFunction() = func
and vsentry_1712.(LocalVariable).getFunction() = func
and vdentry_1713.(LocalVariable).getFunction() = func
and vtentry_1714.(LocalVariable).getFunction() = func
and vqentry_1715.(LocalVariable).getFunction() = func
and vfont_1686.getFunction() = func
and vglyph_1686.getFunction() = func
and vcode_1688.(LocalVariable).getFunction() = func
and vgnstr_1689.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
