/**
 * @name ghostscript-d2ab84732936b6e7e5a461dc94344902965e9a06-xps_load_sfnt_name
 * @id cpp/ghostscript/d2ab84732936b6e7e5a461dc94344902965e9a06/xps-load-sfnt-name
 * @description ghostscript-d2ab84732936b6e7e5a461dc94344902965e9a06-xps/xpsfont.c-xps_load_sfnt_name CVE-2017-9610
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vfont_166, Variable voffset_169, Variable v__func__, ExprStmt target_2, ExprStmt target_3, LogicalOrExpr target_4, ExprStmt target_5, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=voffset_169
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(Literal).getValue()="6"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="length"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfont_166
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("gs_throw_imp")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=v__func__
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof Literal
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(StringLiteral).getValue()="name table byte offset invalid"
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_0)
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_4.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation())
		and target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vfont_166, Variable voffset_169, Variable vcount_171, Variable vstringoffset_171, Variable v__func__, ExprStmt target_3, ExprStmt target_6, RelationalOperation target_7, ExprStmt target_8, PointerArithmeticOperation target_9, ExprStmt target_10, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vstringoffset_171
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=voffset_169
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="length"
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfont_166
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=voffset_169
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(Literal).getValue()="6"
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vcount_171
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(Literal).getValue()="12"
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="length"
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfont_166
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("gs_throw_imp")
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=v__func__
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof Literal
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(StringLiteral).getValue()="name table invalid"
		and (func.getEntryPoint().(BlockStmt).getStmt(13)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(13).getFollowingStmt()=target_1)
		and target_3.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getLocation())
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_7.getGreaterOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getLocation())
		and target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation())
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_9.getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation())
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_10.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_2(Parameter vfont_166, Variable voffset_169, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=voffset_169
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xps_find_sfnt_table")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfont_166
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(StringLiteral).getValue()="name"
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("int")
}

predicate func_3(Parameter vfont_166, Variable voffset_169, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("byte *")
		and target_3.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="data"
		and target_3.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfont_166
		and target_3.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=voffset_169
}

predicate func_4(Variable voffset_169, LogicalOrExpr target_4) {
		target_4.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=voffset_169
		and target_4.getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_4.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_4.getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="6"
}

predicate func_5(Variable v__func__, ExprStmt target_5) {
		target_5.getExpr().(FunctionCall).getTarget().hasName("gs_throw_imp")
		and target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=v__func__
		and target_5.getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_5.getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_5.getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_5.getExpr().(FunctionCall).getArgument(4) instanceof Literal
		and target_5.getExpr().(FunctionCall).getArgument(5).(StringLiteral).getValue()="cannot find name table"
}

predicate func_6(Variable vcount_171, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcount_171
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("u16")
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("byte *")
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="2"
}

predicate func_7(Variable vcount_171, RelationalOperation target_7) {
		 (target_7 instanceof GTExpr or target_7 instanceof LTExpr)
		and target_7.getLesserOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_7.getGreaterOperand().(AddExpr).getAnOperand().(Literal).getValue()="6"
		and target_7.getGreaterOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vcount_171
		and target_7.getGreaterOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(Literal).getValue()="12"
}

predicate func_8(Variable vstringoffset_171, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vstringoffset_171
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("u16")
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("byte *")
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="4"
}

predicate func_9(Variable voffset_169, Variable vstringoffset_171, PointerArithmeticOperation target_9) {
		target_9.getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("byte *")
		and target_9.getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vstringoffset_171
		and target_9.getAnOperand().(VariableAccess).getTarget()=voffset_169
}

predicate func_10(Variable v__func__, ExprStmt target_10) {
		target_10.getExpr().(FunctionCall).getTarget().hasName("gs_throw_imp")
		and target_10.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=v__func__
		and target_10.getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_10.getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_10.getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_10.getExpr().(FunctionCall).getArgument(4) instanceof Literal
		and target_10.getExpr().(FunctionCall).getArgument(5).(StringLiteral).getValue()="name table too short"
}

from Function func, Parameter vfont_166, Variable voffset_169, Variable vcount_171, Variable vstringoffset_171, Variable v__func__, ExprStmt target_2, ExprStmt target_3, LogicalOrExpr target_4, ExprStmt target_5, ExprStmt target_6, RelationalOperation target_7, ExprStmt target_8, PointerArithmeticOperation target_9, ExprStmt target_10
where
not func_0(vfont_166, voffset_169, v__func__, target_2, target_3, target_4, target_5, func)
and not func_1(vfont_166, voffset_169, vcount_171, vstringoffset_171, v__func__, target_3, target_6, target_7, target_8, target_9, target_10, func)
and func_2(vfont_166, voffset_169, target_2)
and func_3(vfont_166, voffset_169, target_3)
and func_4(voffset_169, target_4)
and func_5(v__func__, target_5)
and func_6(vcount_171, target_6)
and func_7(vcount_171, target_7)
and func_8(vstringoffset_171, target_8)
and func_9(voffset_169, vstringoffset_171, target_9)
and func_10(v__func__, target_10)
and vfont_166.getType().hasName("xps_font_t *")
and voffset_169.getType().hasName("int")
and vcount_171.getType().hasName("int")
and vstringoffset_171.getType().hasName("int")
and v__func__.getType() instanceof ArrayType
and vfont_166.getFunction() = func
and voffset_169.(LocalVariable).getFunction() = func
and vcount_171.(LocalVariable).getFunction() = func
and vstringoffset_171.(LocalVariable).getFunction() = func
and not v__func__.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
