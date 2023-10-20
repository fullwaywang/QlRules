/**
 * @name libarchive-1e18cbb71-parse_escapes
 * @id cpp/libarchive/1e18cbb71/parse-escapes
 * @description libarchive-1e18cbb71-libarchive/archive_read_support_format_mtree.c-parse_escapes CVE-2015-8925
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(SwitchCase target_0 |
		target_0.getExpr().(CharLiteral).getValue()="92"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Variable vc_1717, ArrayExpr target_4, ExprStmt target_5, ExprStmt target_6) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vc_1717
		and target_1.getExpr().(AssignExpr).getRValue().(CharLiteral).getValue()="92"
		and target_1.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_4
		and target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
		and target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_6.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vsrc_1714, ArrayExpr target_4, ExprStmt target_7) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(PrefixIncrExpr).getOperand().(VariableAccess).getTarget()=vsrc_1714
		and target_2.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_4
		and target_7.getExpr().(PrefixIncrExpr).getOperand().(VariableAccess).getLocation().isBefore(target_2.getExpr().(PrefixIncrExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_3(ArrayExpr target_4, Function func) {
	exists(BreakStmt target_3 |
		target_3.toString() = "break;"
		and target_3.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_4
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(Parameter vsrc_1714, ArrayExpr target_4) {
		target_4.getArrayBase().(VariableAccess).getTarget()=vsrc_1714
		and target_4.getArrayOffset().(Literal).getValue()="0"
}

predicate func_5(Variable vc_1717, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vc_1717
		and target_5.getExpr().(AssignExpr).getRValue().(CharLiteral).getValue()="11"
}

predicate func_6(Variable vc_1717, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vc_1717
}

predicate func_7(Parameter vsrc_1714, ExprStmt target_7) {
		target_7.getExpr().(PrefixIncrExpr).getOperand().(VariableAccess).getTarget()=vsrc_1714
}

from Function func, Parameter vsrc_1714, Variable vc_1717, ArrayExpr target_4, ExprStmt target_5, ExprStmt target_6, ExprStmt target_7
where
not func_0(func)
and not func_1(vc_1717, target_4, target_5, target_6)
and not func_2(vsrc_1714, target_4, target_7)
and not func_3(target_4, func)
and func_4(vsrc_1714, target_4)
and func_5(vc_1717, target_5)
and func_6(vc_1717, target_6)
and func_7(vsrc_1714, target_7)
and vsrc_1714.getType().hasName("char *")
and vc_1717.getType().hasName("char")
and vsrc_1714.getParentScope+() = func
and vc_1717.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
