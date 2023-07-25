/**
 * @name ghostscript-c53183d4e7103e87368b7cfa15367a47d559e323-xps_true_callback_glyph_name
 * @id cpp/ghostscript/c53183d4e7103e87368b7cfa15367a47d559e323/xps-true-callback-glyph-name
 * @description ghostscript-c53183d4e7103e87368b7cfa15367a47d559e323-xps/xpsttf.c-xps_true_callback_glyph_name CVE-2017-9619
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Parameter vglyph_136, ExprStmt target_2, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vglyph_136
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(BitwiseOrExpr).getValue()="3221225472"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignSubExpr).getLValue().(VariableAccess).getTarget()=vglyph_136
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignSubExpr).getRValue().(BitwiseOrExpr).getValue()="3221225472"
		and (func.getEntryPoint().(BlockStmt).getStmt(6)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(6).getFollowingStmt()=target_1)
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vglyph_136, ExprStmt target_2) {
		target_2.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getTarget()=vglyph_136
		and target_2.getExpr().(AssignSubExpr).getRValue().(Literal).getValue()="29"
}

from Function func, Parameter vglyph_136, ExprStmt target_2
where
not func_1(vglyph_136, target_2, func)
and func_2(vglyph_136, target_2)
and vglyph_136.getType().hasName("gs_glyph")
and vglyph_136.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
