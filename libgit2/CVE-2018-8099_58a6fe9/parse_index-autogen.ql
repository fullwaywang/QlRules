/**
 * @name libgit2-58a6fe94cb851f71214dbefac3f9bffee437d6fe-parse_index
 * @id cpp/libgit2/58a6fe94cb851f71214dbefac3f9bffee437d6fe/parse-index
 * @description libgit2-58a6fe94cb851f71214dbefac3f9bffee437d6fe-src/index.c-parse_index CVE-2018-8099
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vindex_2458, Parameter vbuffer_2458, Parameter vbuffer_size_2458, Variable verror_2460, Variable vlast_2464, Variable ventry_size_2502, BlockStmt target_9, ExprStmt target_10, AddressOfExpr target_11, ExprStmt target_12, ExprStmt target_13, LogicalAndExpr target_14, RelationalOperation target_15, ExprStmt target_16, ExprStmt target_17, EqualityOperation target_8) {
	exists(RelationalOperation target_0 |
		 (target_0 instanceof GTExpr or target_0 instanceof LTExpr)
		and target_0.getLesserOperand().(AssignExpr).getLValue().(VariableAccess).getTarget()=verror_2460
		and target_0.getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("read_entry")
		and target_0.getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0) instanceof AddressOfExpr
		and target_0.getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=ventry_size_2502
		and target_0.getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vindex_2458
		and target_0.getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vbuffer_2458
		and target_0.getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vbuffer_size_2458
		and target_0.getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vlast_2464
		and target_0.getGreaterOperand() instanceof Literal
		and target_0.getParent().(IfStmt).getThen()=target_9
		and target_10.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getLocation())
		and target_0.getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_11.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_12.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getLocation())
		and target_0.getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getLocation().isBefore(target_13.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation())
		and target_14.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_0.getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getLocation())
		and target_0.getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getLocation().isBefore(target_15.getLesserOperand().(VariableAccess).getLocation())
		and target_16.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getLesserOperand().(AssignExpr).getLValue().(VariableAccess).getLocation())
		and target_17.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getLocation())
		and target_0.getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getLocation().isBefore(target_8.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable ventry_2501, AddressOfExpr target_1) {
		target_1.getOperand().(VariableAccess).getTarget()=ventry_2501
		and target_1.getParent().(FunctionCall).getParent().(Initializer).getExpr() instanceof FunctionCall
}

predicate func_2(Parameter vindex_2458, VariableAccess target_2) {
		target_2.getTarget()=vindex_2458
		and target_2.getParent().(FunctionCall).getParent().(Initializer).getExpr() instanceof FunctionCall
}

predicate func_3(Parameter vbuffer_2458, VariableAccess target_3) {
		target_3.getTarget()=vbuffer_2458
		and target_3.getParent().(FunctionCall).getParent().(Initializer).getExpr() instanceof FunctionCall
}

predicate func_4(Parameter vbuffer_size_2458, VariableAccess target_4) {
		target_4.getTarget()=vbuffer_size_2458
		and target_4.getParent().(FunctionCall).getParent().(Initializer).getExpr() instanceof FunctionCall
}

predicate func_5(Variable vlast_2464, VariableAccess target_5) {
		target_5.getTarget()=vlast_2464
		and target_5.getParent().(FunctionCall).getParent().(Initializer).getExpr() instanceof FunctionCall
}

predicate func_7(Parameter vindex_2458, Parameter vbuffer_2458, Parameter vbuffer_size_2458, Variable vlast_2464, Initializer target_7) {
		target_7.getExpr().(FunctionCall).getTarget().hasName("read_entry")
		and target_7.getExpr().(FunctionCall).getArgument(0) instanceof AddressOfExpr
		and target_7.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vindex_2458
		and target_7.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vbuffer_2458
		and target_7.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vbuffer_size_2458
		and target_7.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vlast_2464
}

predicate func_8(Variable ventry_size_2502, BlockStmt target_9, EqualityOperation target_8) {
		target_8.getAnOperand().(VariableAccess).getTarget()=ventry_size_2502
		and target_8.getAnOperand() instanceof Literal
		and target_8.getParent().(IfStmt).getThen()=target_9
}

predicate func_9(Variable verror_2460, BlockStmt target_9) {
		target_9.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=verror_2460
		and target_9.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("index_error_invalid")
		and target_9.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(StringLiteral).getValue()="invalid entry"
		and target_9.getStmt(1).(GotoStmt).toString() = "goto ..."
		and target_9.getStmt(1).(GotoStmt).getName() ="done"
}

predicate func_10(Parameter vindex_2458, ExprStmt target_10) {
		target_10.getExpr().(FunctionCall).getTarget().hasName("git_idxmap_resize")
		and target_10.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="entries_map"
		and target_10.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vindex_2458
		and target_10.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="entry_count"
}

predicate func_11(Parameter vindex_2458, AddressOfExpr target_11) {
		target_11.getOperand().(PointerFieldAccess).getTarget().getName()="entries"
		and target_11.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vindex_2458
}

predicate func_12(Parameter vbuffer_2458, ExprStmt target_12) {
		target_12.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vbuffer_2458
}

predicate func_13(Parameter vbuffer_2458, Variable ventry_size_2502, ExprStmt target_13) {
		target_13.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vbuffer_2458
		and target_13.getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getTarget()=ventry_size_2502
}

predicate func_14(Parameter vbuffer_size_2458, LogicalAndExpr target_14) {
		target_14.getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getTarget().getName()="entry_count"
		and target_14.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vbuffer_size_2458
}

predicate func_15(Parameter vbuffer_size_2458, Variable ventry_size_2502, RelationalOperation target_15) {
		 (target_15 instanceof GEExpr or target_15 instanceof LEExpr)
		and target_15.getGreaterOperand().(VariableAccess).getTarget()=ventry_size_2502
		and target_15.getLesserOperand().(VariableAccess).getTarget()=vbuffer_size_2458
}

predicate func_16(Variable verror_2460, ExprStmt target_16) {
		target_16.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=verror_2460
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("index_error_invalid")
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(StringLiteral).getValue()="ran out of data while parsing"
}

predicate func_17(Variable vlast_2464, ExprStmt target_17) {
		target_17.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlast_2464
}

from Function func, Parameter vindex_2458, Parameter vbuffer_2458, Parameter vbuffer_size_2458, Variable verror_2460, Variable vlast_2464, Variable ventry_2501, Variable ventry_size_2502, AddressOfExpr target_1, VariableAccess target_2, VariableAccess target_3, VariableAccess target_4, VariableAccess target_5, Initializer target_7, EqualityOperation target_8, BlockStmt target_9, ExprStmt target_10, AddressOfExpr target_11, ExprStmt target_12, ExprStmt target_13, LogicalAndExpr target_14, RelationalOperation target_15, ExprStmt target_16, ExprStmt target_17
where
not func_0(vindex_2458, vbuffer_2458, vbuffer_size_2458, verror_2460, vlast_2464, ventry_size_2502, target_9, target_10, target_11, target_12, target_13, target_14, target_15, target_16, target_17, target_8)
and func_1(ventry_2501, target_1)
and func_2(vindex_2458, target_2)
and func_3(vbuffer_2458, target_3)
and func_4(vbuffer_size_2458, target_4)
and func_5(vlast_2464, target_5)
and func_7(vindex_2458, vbuffer_2458, vbuffer_size_2458, vlast_2464, target_7)
and func_8(ventry_size_2502, target_9, target_8)
and func_9(verror_2460, target_9)
and func_10(vindex_2458, target_10)
and func_11(vindex_2458, target_11)
and func_12(vbuffer_2458, target_12)
and func_13(vbuffer_2458, ventry_size_2502, target_13)
and func_14(vbuffer_size_2458, target_14)
and func_15(vbuffer_size_2458, ventry_size_2502, target_15)
and func_16(verror_2460, target_16)
and func_17(vlast_2464, target_17)
and vindex_2458.getType().hasName("git_index *")
and vbuffer_2458.getType().hasName("const char *")
and vbuffer_size_2458.getType().hasName("size_t")
and verror_2460.getType().hasName("int")
and vlast_2464.getType().hasName("const char *")
and ventry_2501.getType().hasName("git_index_entry *")
and ventry_size_2502.getType().hasName("size_t")
and vindex_2458.getParentScope+() = func
and vbuffer_2458.getParentScope+() = func
and vbuffer_size_2458.getParentScope+() = func
and verror_2460.getParentScope+() = func
and vlast_2464.getParentScope+() = func
and ventry_2501.getParentScope+() = func
and ventry_size_2502.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
