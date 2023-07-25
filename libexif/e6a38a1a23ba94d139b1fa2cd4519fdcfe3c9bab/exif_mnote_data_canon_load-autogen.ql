/**
 * @name libexif-e6a38a1a23ba94d139b1fa2cd4519fdcfe3c9bab-exif_mnote_data_canon_load
 * @id cpp/libexif/e6a38a1a23ba94d139b1fa2cd4519fdcfe3c9bab/exif-mnote-data-canon-load
 * @description libexif-e6a38a1a23ba94d139b1fa2cd4519fdcfe3c9bab-libexif/canon/exif-mnote-data-canon.c-exif_mnote_data_canon_load CVE-2020-13114
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vn_204, Variable vtcount_206, ArrayExpr target_2) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getType().hasName("long")
		and target_0.getExpr().(AssignAddExpr).getRValue().(FunctionCall).getTarget().hasName("mnote_canon_entry_count_values")
		and target_0.getExpr().(AssignAddExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="entries"
		and target_0.getExpr().(AssignAddExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vn_204
		and target_0.getExpr().(AssignAddExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vtcount_206
		and target_2.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignAddExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vne_201, Variable vtcount_206, ExprStmt target_3, ExprStmt target_4) {
	exists(IfStmt target_1 |
		target_1.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("long")
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="1000000"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("exif_mem_free")
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="mem"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vne_201
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="data"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="entries"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vtcount_206
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("exif_log")
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="log"
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vne_201
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="ExifMnoteCanon"
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Failsafe tag size overflow (%lu > %ld)"
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getType().hasName("long")
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(Literal).getValue()="1000000"
		and target_1.getThen().(BlockStmt).getStmt(2).(BreakStmt).toString() = "break;"
		and target_3.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation().isBefore(target_4.getExpr().(PrefixIncrExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_2(Variable vn_204, Variable vtcount_206, ArrayExpr target_2) {
		target_2.getArrayBase().(PointerFieldAccess).getTarget().getName()="entries"
		and target_2.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vn_204
		and target_2.getArrayOffset().(VariableAccess).getTarget()=vtcount_206
}

predicate func_3(Parameter vne_201, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("exif_log")
		and target_3.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="log"
		and target_3.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vne_201
		and target_3.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="ExifMnoteCanon"
		and target_3.getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Could not allocate %lu byte(s)."
}

predicate func_4(Variable vtcount_206, ExprStmt target_4) {
		target_4.getExpr().(PrefixIncrExpr).getOperand().(VariableAccess).getTarget()=vtcount_206
}

from Function func, Parameter vne_201, Variable vn_204, Variable vtcount_206, ArrayExpr target_2, ExprStmt target_3, ExprStmt target_4
where
not func_0(vn_204, vtcount_206, target_2)
and not func_1(vne_201, vtcount_206, target_3, target_4)
and func_2(vn_204, vtcount_206, target_2)
and func_3(vne_201, target_3)
and func_4(vtcount_206, target_4)
and vne_201.getType().hasName("ExifMnoteData *")
and vn_204.getType().hasName("ExifMnoteDataCanon *")
and vtcount_206.getType().hasName("size_t")
and vne_201.getParentScope+() = func
and vn_204.getParentScope+() = func
and vtcount_206.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
