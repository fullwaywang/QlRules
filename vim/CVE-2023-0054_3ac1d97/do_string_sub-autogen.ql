/**
 * @name vim-3ac1d97a1d9353490493d30088256360435f7731-do_string_sub
 * @id cpp/vim/3ac1d97a1d9353490493d30088256360435f7731/do-string-sub
 * @description vim-3ac1d97a1d9353490493d30088256360435f7731-src/eval.c-do_string_sub CVE-2023-0054
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vsublen_7264, Variable vga_7270, ExprStmt target_1, SubExpr target_2, ExprStmt target_3, AddressOfExpr target_4) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vsublen_7264
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ga_clear")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vga_7270
		and target_0.getThen().(BlockStmt).getStmt(1).(BreakStmt).toString() = "break;"
		and target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_2.getLeftOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation())
		and target_3.getExpr().(AssignAddExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getLocation().isBefore(target_4.getOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vsublen_7264, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsublen_7264
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("vim_regsub")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(Literal).getValue()="2"
}

predicate func_2(Variable vsublen_7264, SubExpr target_2) {
		target_2.getLeftOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vsublen_7264
		and target_2.getRightOperand().(PointerArithmeticOperation).getLeftOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="endp"
		and target_2.getRightOperand().(PointerArithmeticOperation).getLeftOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_2.getRightOperand().(PointerArithmeticOperation).getRightOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="startp"
		and target_2.getRightOperand().(PointerArithmeticOperation).getRightOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
}

predicate func_3(Variable vga_7270, ExprStmt target_3) {
		target_3.getExpr().(AssignAddExpr).getLValue().(ValueFieldAccess).getTarget().getName()="ga_len"
		and target_3.getExpr().(AssignAddExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vga_7270
}

predicate func_4(Variable vga_7270, AddressOfExpr target_4) {
		target_4.getOperand().(VariableAccess).getTarget()=vga_7270
}

from Function func, Variable vsublen_7264, Variable vga_7270, ExprStmt target_1, SubExpr target_2, ExprStmt target_3, AddressOfExpr target_4
where
not func_0(vsublen_7264, vga_7270, target_1, target_2, target_3, target_4)
and func_1(vsublen_7264, target_1)
and func_2(vsublen_7264, target_2)
and func_3(vga_7270, target_3)
and func_4(vga_7270, target_4)
and vsublen_7264.getType().hasName("int")
and vga_7270.getType().hasName("garray_T")
and vsublen_7264.getParentScope+() = func
and vga_7270.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
