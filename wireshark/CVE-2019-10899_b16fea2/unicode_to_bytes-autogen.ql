/**
 * @name wireshark-b16fea2f175a3297edac118c8844c7987d31c1cb-unicode_to_bytes
 * @id cpp/wireshark/b16fea2f175a3297edac118c8844c7987d31c1cb/unicode-to-bytes
 * @description wireshark-b16fea2f175a3297edac118c8844c7987d31c1cb-epan/dissectors/packet-srvloc.c-unicode_to_bytes CVE-2019-10899
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vi_446, BlockStmt target_5, ExprStmt target_6) {
	exists(EqualityOperation target_0 |
		target_0.getAnOperand().(VariableAccess).getTarget()=vi_446
		and target_0.getAnOperand().(Literal).getValue()="0"
		and target_0.getParent().(IfStmt).getThen()=target_5
		and target_6.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_1(EqualityOperation target_4, Function func) {
	exists(BreakStmt target_1 |
		target_1.toString() = "break;"
		and target_1.getParent().(IfStmt).getCondition()=target_4
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Variable vascii_text_445, Variable vi_446, Variable vc_char1_447, EqualityOperation target_7, ExprStmt target_6, ExprStmt target_8, EqualityOperation target_4, ExprStmt target_9) {
	exists(IfStmt target_2 |
		target_2.getCondition() instanceof EqualityOperation
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vi_446
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BreakStmt).toString() = "break;"
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget()=vi_446
		and target_2.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vc_char1_447
		and target_2.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vascii_text_445
		and target_2.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_446
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(3)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_7
		and target_6.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_2.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_2.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_8.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_4.getAnOperand().(VariableAccess).getLocation().isBefore(target_2.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
		and target_2.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_9.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation()))
}

/*predicate func_3(Variable vi_446, EqualityOperation target_4, ExprStmt target_10) {
	exists(IfStmt target_3 |
		target_3.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vi_446
		and target_3.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_3.getThen().(BreakStmt).toString() = "break;"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_3
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
		and target_3.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_10.getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getLocation()))
}

*/
predicate func_4(Variable vc_char1_447, BlockStmt target_5, EqualityOperation target_4) {
		target_4.getAnOperand().(VariableAccess).getTarget()=vc_char1_447
		and target_4.getAnOperand().(Literal).getValue()="0"
		and target_4.getParent().(IfStmt).getThen()=target_5
}

predicate func_5(Variable vascii_text_445, Variable vi_446, Variable vc_char1_447, BlockStmt target_5) {
		target_5.getStmt(0).(ExprStmt).getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget()=vi_446
		and target_5.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vc_char1_447
		and target_5.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vascii_text_445
		and target_5.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_446
}

predicate func_6(Variable vascii_text_445, Variable vi_446, Variable vc_char1_447, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vc_char1_447
		and target_6.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vascii_text_445
		and target_6.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_446
}

predicate func_7(EqualityOperation target_7) {
		target_7.getAnOperand().(Literal).getValue()="0"
}

predicate func_8(Variable vascii_text_445, Variable vi_446, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vascii_text_445
		and target_8.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_446
}

predicate func_9(Variable vc_char1_447, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vc_char1_447
}

predicate func_10(Variable vi_446, ExprStmt target_10) {
		target_10.getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget()=vi_446
}

from Function func, Variable vascii_text_445, Variable vi_446, Variable vc_char1_447, EqualityOperation target_4, BlockStmt target_5, ExprStmt target_6, EqualityOperation target_7, ExprStmt target_8, ExprStmt target_9, ExprStmt target_10
where
not func_0(vi_446, target_5, target_6)
and not func_1(target_4, func)
and not func_2(vascii_text_445, vi_446, vc_char1_447, target_7, target_6, target_8, target_4, target_9)
and func_4(vc_char1_447, target_5, target_4)
and func_5(vascii_text_445, vi_446, vc_char1_447, target_5)
and func_6(vascii_text_445, vi_446, vc_char1_447, target_6)
and func_7(target_7)
and func_8(vascii_text_445, vi_446, target_8)
and func_9(vc_char1_447, target_9)
and func_10(vi_446, target_10)
and vascii_text_445.getType().hasName("const guint8 *")
and vi_446.getType().hasName("int")
and vc_char1_447.getType().hasName("guint8")
and vascii_text_445.getParentScope+() = func
and vi_446.getParentScope+() = func
and vc_char1_447.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
