/**
 * @name ghostscript-450da26a76286a8342ec0864b3d113856709f8f6-lprn_is_black
 * @id cpp/ghostscript/450da26a76286a8342ec0864b3d113856709f8f6/lprn-is-black
 * @description ghostscript-450da26a76286a8342ec0864b3d113856709f8f6-contrib/lips4/gdevlprn.c-lprn_is_black CVE-2020-16287
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vbx_324, Variable vlprn_326, Variable vbpl_329, Variable vx_330, ExprStmt target_2, RelationalOperation target_3, PostfixIncrExpr target_4, EqualityOperation target_5) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vbx_324
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="nBw"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vlprn_326
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vx_330
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vbpl_329
		and target_2.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getLocation())
		and target_3.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_4.getOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_5.getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation()))
}

predicate func_1(Variable vx_330, Variable vp_331, IfStmt target_1) {
		target_1.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vp_331
		and target_1.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vx_330
		and target_1.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getThen().(ReturnStmt).getExpr().(Literal).getValue()="1"
}

predicate func_2(Parameter vbx_324, Variable vlprn_326, Variable vbpl_329, Variable vp_331, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vp_331
		and target_2.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="ImageBuf"
		and target_2.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vlprn_326
		and target_2.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vbpl_329
		and target_2.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vbx_324
		and target_2.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="nBw"
}

predicate func_3(Variable vlprn_326, Variable vx_330, RelationalOperation target_3) {
		 (target_3 instanceof GTExpr or target_3 instanceof LTExpr)
		and target_3.getLesserOperand().(VariableAccess).getTarget()=vx_330
		and target_3.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="nBw"
		and target_3.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vlprn_326
}

predicate func_4(Variable vx_330, PostfixIncrExpr target_4) {
		target_4.getOperand().(VariableAccess).getTarget()=vx_330
}

predicate func_5(Variable vx_330, Variable vp_331, EqualityOperation target_5) {
		target_5.getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vp_331
		and target_5.getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vx_330
		and target_5.getAnOperand().(Literal).getValue()="0"
}

from Function func, Parameter vbx_324, Variable vlprn_326, Variable vbpl_329, Variable vx_330, Variable vp_331, IfStmt target_1, ExprStmt target_2, RelationalOperation target_3, PostfixIncrExpr target_4, EqualityOperation target_5
where
not func_0(vbx_324, vlprn_326, vbpl_329, vx_330, target_2, target_3, target_4, target_5)
and func_1(vx_330, vp_331, target_1)
and func_2(vbx_324, vlprn_326, vbpl_329, vp_331, target_2)
and func_3(vlprn_326, vx_330, target_3)
and func_4(vx_330, target_4)
and func_5(vx_330, vp_331, target_5)
and vbx_324.getType().hasName("int")
and vlprn_326.getType().hasName("gx_device_lprn *const")
and vbpl_329.getType().hasName("int")
and vx_330.getType().hasName("int")
and vp_331.getType().hasName("byte *")
and vbx_324.getFunction() = func
and vlprn_326.(LocalVariable).getFunction() = func
and vbpl_329.(LocalVariable).getFunction() = func
and vx_330.(LocalVariable).getFunction() = func
and vp_331.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
