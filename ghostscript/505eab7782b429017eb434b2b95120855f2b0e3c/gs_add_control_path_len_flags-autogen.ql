/**
 * @name ghostscript-505eab7782b429017eb434b2b95120855f2b0e3c-gs_add_control_path_len_flags
 * @id cpp/ghostscript/505eab7782b429017eb434b2b95120855f2b0e3c/gs-add-control-path-len-flags
 * @description ghostscript-505eab7782b429017eb434b2b95120855f2b0e3c-base/gslibctx.c-gs_add_control_path_len_flags CVE-2023-36664
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, StringLiteral target_0) {
		target_0.getValue()="gp_validate_path"
		and not target_0.getValue()="gs_add_control_path_len"
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Parameter vpath_714, Parameter vlen_714, Variable vcore_718, Variable vbuffer_719, Variable vrlen_720, LogicalOrExpr target_10, EqualityOperation target_11, ExprStmt target_9, EqualityOperation target_12, EqualityOperation target_13, AddressOfExpr target_14, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlen_714
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="5"
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("memcmp")
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpath_714
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="%pipe"
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(Literal).getValue()="5"
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbuffer_719
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(ExprCall).getExpr() instanceof PointerDereferenceExpr
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(ExprCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="memory"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(ExprCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcore_718
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(ExprCall).getArgument(1).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vlen_714
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(ExprCall).getArgument(1).(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(ExprCall).getArgument(2).(StringLiteral).getValue()="gs_add_control_path_len"
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vbuffer_719
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuffer_719
		and target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpath_714
		and target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vlen_714
		and target_1.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbuffer_719
		and target_1.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vlen_714
		and target_1.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vrlen_720
		and target_1.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vlen_714
		and target_1.getElse().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_1.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbuffer_719
		and target_1.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getTarget().getName()="alloc_bytes"
		and target_1.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(ExprCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="memory"
		and target_1.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(ExprCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcore_718
		and target_1.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(ExprCall).getArgument(1).(VariableAccess).getTarget()=vrlen_720
		and target_1.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(ExprCall).getArgument(2).(StringLiteral).getValue()="gs_add_control_path_len"
		and target_1.getElse().(BlockStmt).getStmt(2) instanceof IfStmt
		and target_1.getElse().(BlockStmt).getStmt(3) instanceof IfStmt
		and target_1.getElse().(BlockStmt).getStmt(4) instanceof ExprStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(8)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(8).getFollowingStmt()=target_1)
		and target_10.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_11.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_9.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getLocation())
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(ExprCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_12.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_13.getAnOperand().(VariableAccess).getLocation())
		and target_1.getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_14.getOperand().(VariableAccess).getLocation()))
}

/*predicate func_3(Variable vcore_718, EqualityOperation target_12) {
	exists(PointerFieldAccess target_3 |
		target_3.getTarget().getName()="memory"
		and target_3.getQualifier().(VariableAccess).getTarget()=vcore_718
		and target_3.getQualifier().(VariableAccess).getLocation().isBefore(target_12.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

*/
/*predicate func_4(Variable vcore_718, PointerDereferenceExpr target_4) {
		target_4.getOperand().(ValueFieldAccess).getTarget().getName()="alloc_bytes"
		and target_4.getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="procs"
		and target_4.getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="memory"
		and target_4.getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcore_718
}

*/
predicate func_5(Variable vcore_718, Variable vrlen_720, PointerFieldAccess target_5) {
		target_5.getTarget().getName()="memory"
		and target_5.getQualifier().(VariableAccess).getTarget()=vcore_718
		and target_5.getParent().(ExprCall).getParent().(AssignExpr).getRValue().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getTarget().getName()="alloc_bytes"
		and target_5.getParent().(ExprCall).getParent().(AssignExpr).getRValue().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="procs"
		and target_5.getParent().(ExprCall).getParent().(AssignExpr).getRValue().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="memory"
		and target_5.getParent().(ExprCall).getParent().(AssignExpr).getRValue().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcore_718
		and target_5.getParent().(ExprCall).getParent().(AssignExpr).getRValue().(ExprCall).getArgument(1).(VariableAccess).getTarget()=vrlen_720
		and target_5.getParent().(ExprCall).getParent().(AssignExpr).getRValue().(ExprCall).getArgument(2) instanceof StringLiteral
}

predicate func_6(Variable vbuffer_719, Function func, IfStmt target_6) {
		target_6.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vbuffer_719
		and target_6.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_6
}

predicate func_7(Parameter vpath_714, Parameter vlen_714, Variable vbuffer_719, Variable vrlen_720, Function func, IfStmt target_7) {
		target_7.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("gp_file_name_reduce")
		and target_7.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpath_714
		and target_7.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vlen_714
		and target_7.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vbuffer_719
		and target_7.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vrlen_720
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_7
}

predicate func_8(Variable vbuffer_719, Variable vrlen_720, Function func, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbuffer_719
		and target_8.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vrlen_720
		and target_8.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_8
}

predicate func_9(Parameter vlen_714, Variable vrlen_720, Function func, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vrlen_720
		and target_9.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vlen_714
		and target_9.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_9
}

predicate func_10(Parameter vpath_714, Parameter vlen_714, LogicalOrExpr target_10) {
		target_10.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vpath_714
		and target_10.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_10.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vlen_714
		and target_10.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
}

predicate func_11(Parameter vpath_714, Parameter vlen_714, Variable vbuffer_719, Variable vrlen_720, EqualityOperation target_11) {
		target_11.getAnOperand().(FunctionCall).getTarget().hasName("gp_file_name_reduce")
		and target_11.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpath_714
		and target_11.getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vlen_714
		and target_11.getAnOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vbuffer_719
		and target_11.getAnOperand().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vrlen_720
}

predicate func_12(Variable vcore_718, EqualityOperation target_12) {
		target_12.getAnOperand().(PointerFieldAccess).getTarget().getName()="memory"
		and target_12.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcore_718
		and target_12.getAnOperand().(Literal).getValue()="0"
}

predicate func_13(Variable vbuffer_719, EqualityOperation target_13) {
		target_13.getAnOperand().(VariableAccess).getTarget()=vbuffer_719
		and target_13.getAnOperand().(Literal).getValue()="0"
}

predicate func_14(Variable vrlen_720, AddressOfExpr target_14) {
		target_14.getOperand().(VariableAccess).getTarget()=vrlen_720
}

from Function func, Parameter vpath_714, Parameter vlen_714, Variable vcore_718, Variable vbuffer_719, Variable vrlen_720, StringLiteral target_0, PointerFieldAccess target_5, IfStmt target_6, IfStmt target_7, ExprStmt target_8, ExprStmt target_9, LogicalOrExpr target_10, EqualityOperation target_11, EqualityOperation target_12, EqualityOperation target_13, AddressOfExpr target_14
where
func_0(func, target_0)
and not func_1(vpath_714, vlen_714, vcore_718, vbuffer_719, vrlen_720, target_10, target_11, target_9, target_12, target_13, target_14, func)
and func_5(vcore_718, vrlen_720, target_5)
and func_6(vbuffer_719, func, target_6)
and func_7(vpath_714, vlen_714, vbuffer_719, vrlen_720, func, target_7)
and func_8(vbuffer_719, vrlen_720, func, target_8)
and func_9(vlen_714, vrlen_720, func, target_9)
and func_10(vpath_714, vlen_714, target_10)
and func_11(vpath_714, vlen_714, vbuffer_719, vrlen_720, target_11)
and func_12(vcore_718, target_12)
and func_13(vbuffer_719, target_13)
and func_14(vrlen_720, target_14)
and vpath_714.getType().hasName("const char *")
and vlen_714.getType().hasName("size_t")
and vcore_718.getType().hasName("gs_lib_ctx_core_t *")
and vbuffer_719.getType().hasName("char *")
and vrlen_720.getType().hasName("uint")
and vpath_714.getFunction() = func
and vlen_714.getFunction() = func
and vcore_718.(LocalVariable).getFunction() = func
and vbuffer_719.(LocalVariable).getFunction() = func
and vrlen_720.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
