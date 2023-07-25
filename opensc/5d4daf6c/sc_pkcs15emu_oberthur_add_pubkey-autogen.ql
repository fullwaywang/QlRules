/**
 * @name opensc-5d4daf6c-sc_pkcs15emu_oberthur_add_pubkey
 * @id cpp/opensc/5d4daf6c/sc-pkcs15emu-oberthur-add-pubkey
 * @description opensc-5d4daf6c-src/libopensc/pkcs15-oberthur.c-sc_pkcs15emu_oberthur_add_pubkey CVE-2021-42781
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vinfo_blob_579, Variable vlen_580, Variable vinfo_len_580, Variable voffs_580, ExprStmt target_2, PointerArithmeticOperation target_3, IfStmt target_1, RelationalOperation target_4, RelationalOperation target_5, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=voffs_580
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(Literal).getValue()="2"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vlen_580
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vinfo_len_580
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("free")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vinfo_blob_579
		and target_0.getThen().(BlockStmt).getStmt(1).(DoStmt).getCondition() instanceof Literal
		and target_0.getThen().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("int")
		and target_0.getThen().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand() instanceof Literal
		and target_0.getElse() instanceof IfStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(23)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(23).getFollowingStmt()=target_0)
		and target_2.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_3.getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_1.getCondition().(VariableAccess).getLocation())
		and target_4.getLesserOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_5.getLesserOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vkey_obj_577, Variable vinfo_blob_579, Variable vlen_580, Variable voffs_580, Function func, IfStmt target_1) {
		target_1.getCondition().(VariableAccess).getTarget()=vlen_580
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlen_580
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getValue()="254"
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlen_580
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(SubExpr).getValue()="254"
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="label"
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vkey_obj_577
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vinfo_blob_579
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=voffs_580
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="2"
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vlen_580
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1
}

predicate func_2(Variable vinfo_blob_579, Variable vlen_580, Variable voffs_580, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlen_580
		and target_2.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vinfo_blob_579
		and target_2.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=voffs_580
		and target_2.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="1"
		and target_2.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vinfo_blob_579
		and target_2.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=voffs_580
		and target_2.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(HexLiteral).getValue()="256"
}

predicate func_3(Variable vinfo_blob_579, Variable voffs_580, PointerArithmeticOperation target_3) {
		target_3.getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vinfo_blob_579
		and target_3.getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=voffs_580
		and target_3.getAnOperand().(Literal).getValue()="2"
}

predicate func_4(Variable vinfo_len_580, Variable voffs_580, RelationalOperation target_4) {
		 (target_4 instanceof GTExpr or target_4 instanceof LTExpr)
		and target_4.getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=voffs_580
		and target_4.getGreaterOperand().(AddExpr).getAnOperand().(Literal).getValue()="2"
		and target_4.getLesserOperand().(VariableAccess).getTarget()=vinfo_len_580
}

predicate func_5(Variable vinfo_len_580, Variable voffs_580, RelationalOperation target_5) {
		 (target_5 instanceof GTExpr or target_5 instanceof LTExpr)
		and target_5.getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=voffs_580
		and target_5.getGreaterOperand().(AddExpr).getAnOperand().(Literal).getValue()="2"
		and target_5.getLesserOperand().(VariableAccess).getTarget()=vinfo_len_580
}

from Function func, Variable vkey_obj_577, Variable vinfo_blob_579, Variable vlen_580, Variable vinfo_len_580, Variable voffs_580, IfStmt target_1, ExprStmt target_2, PointerArithmeticOperation target_3, RelationalOperation target_4, RelationalOperation target_5
where
not func_0(vinfo_blob_579, vlen_580, vinfo_len_580, voffs_580, target_2, target_3, target_1, target_4, target_5, func)
and func_1(vkey_obj_577, vinfo_blob_579, vlen_580, voffs_580, func, target_1)
and func_2(vinfo_blob_579, vlen_580, voffs_580, target_2)
and func_3(vinfo_blob_579, voffs_580, target_3)
and func_4(vinfo_len_580, voffs_580, target_4)
and func_5(vinfo_len_580, voffs_580, target_5)
and vkey_obj_577.getType().hasName("sc_pkcs15_object")
and vinfo_blob_579.getType().hasName("unsigned char *")
and vlen_580.getType().hasName("size_t")
and vinfo_len_580.getType().hasName("size_t")
and voffs_580.getType().hasName("size_t")
and vkey_obj_577.getParentScope+() = func
and vinfo_blob_579.getParentScope+() = func
and vlen_580.getParentScope+() = func
and vinfo_len_580.getParentScope+() = func
and voffs_580.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
