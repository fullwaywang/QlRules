/**
 * @name libyang-99b5b2a6c0edb9cddbe619b93f2bbd231a828aee-lys_compile_type
 * @id cpp/libyang/99b5b2a6c0edb9cddbe619b93f2bbd231a828aee/lys-compile-type
 * @description libyang-99b5b2a6c0edb9cddbe619b93f2bbd231a828aee-src/tree_schema_compile.c-lys_compile_type CVE-2019-20395
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Variable vu_2843, Variable vtpdf_chain_2852, BlockStmt target_24, ExprStmt target_9) {
	exists(RelationalOperation target_1 |
		 (target_1 instanceof GTExpr or target_1 instanceof LTExpr)
		and target_1.getLesserOperand().(VariableAccess).getTarget()=vu_2843
		and target_1.getGreaterOperand().(ValueFieldAccess).getTarget().getName()="count"
		and target_1.getGreaterOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vtpdf_chain_2852
		and target_1.getParent().(ForStmt).getStmt()=target_24
		and target_9.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getLesserOperand().(VariableAccess).getLocation()))
}

predicate func_2(Variable vu_2843, RelationalOperation target_10) {
	exists(PostfixIncrExpr target_2 |
		target_2.getOperand().(VariableAccess).getTarget()=vu_2843
		and target_2.getOperand().(VariableAccess).getLocation().isBefore(target_10.getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_3(Variable vu_2843, Variable vtpdf_chain_2852, PrefixDecrExpr target_11, ExprStmt target_12) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("type_context *")
		and target_3.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="objs"
		and target_3.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vtpdf_chain_2852
		and target_3.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vu_2843
		and target_11.getOperand().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation())
		and target_3.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation().isBefore(target_12.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation()))
}

predicate func_4(Parameter vctx_2839, Variable vret_2842, Variable vtctx_2849, ExprStmt target_25, ExprStmt target_26) {
	exists(IfStmt target_4 |
		target_4.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="mod"
		and target_4.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("type_context *")
		and target_4.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="mod"
		and target_4.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtctx_2849
		and target_4.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="node"
		and target_4.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("type_context *")
		and target_4.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="node"
		and target_4.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtctx_2849
		and target_4.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="tpdf"
		and target_4.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("type_context *")
		and target_4.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="tpdf"
		and target_4.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtctx_2849
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ly_vlog")
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ctx"
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_2839
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="path"
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_2839
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(StringLiteral).getValue()="Invalid \"%s\" type reference - circular chain of types detected."
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(PointerFieldAccess).getTarget().getName()="name"
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="tpdf"
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtctx_2849
		and target_4.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("free")
		and target_4.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtctx_2849
		and target_4.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_2842
		and target_4.getThen().(BlockStmt).getStmt(3).(GotoStmt).toString() = "goto ..."
		and target_4.getThen().(BlockStmt).getStmt(3).(GotoStmt).getName() ="cleanup"
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_25.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_26.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_4.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation()))
}

predicate func_5(Parameter vctx_2839, Variable vret_2842, Variable vu_2843, Variable vtctx_2849, ExprStmt target_27, IfStmt target_28, ExprStmt target_29) {
	exists(ForStmt target_5 |
		target_5.getInitialization().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vu_2843
		and target_5.getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_5.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vu_2843
		and target_5.getCondition().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getTarget().getName()="count"
		and target_5.getCondition().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="tpdf_chain"
		and target_5.getCondition().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_2839
		and target_5.getUpdate().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vu_2843
		and target_5.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("type_context *")
		and target_5.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="objs"
		and target_5.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="tpdf_chain"
		and target_5.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vu_2843
		and target_5.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="mod"
		and target_5.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="mod"
		and target_5.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="node"
		and target_5.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="node"
		and target_5.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="tpdf"
		and target_5.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("type_context *")
		and target_5.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="tpdf"
		and target_5.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtctx_2849
		and target_5.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ly_vlog")
		and target_5.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ctx"
		and target_5.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="path"
		and target_5.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(StringLiteral).getValue()="Invalid \"%s\" type reference - circular chain of types detected."
		and target_5.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(PointerFieldAccess).getTarget().getName()="name"
		and target_5.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("free")
		and target_5.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtctx_2849
		and target_5.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_2842
		and target_5.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(3).(GotoStmt).toString() = "goto ..."
		and target_5.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(3).(GotoStmt).getName() ="cleanup"
		and target_27.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getCondition().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_28.getCondition().(VariableAccess).getLocation().isBefore(target_5.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
		and target_5.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_29.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation()))
}

predicate func_6(Parameter vctx_2839, Variable vtctx_2849, ExprStmt target_30, ExprStmt target_31, Function func) {
	exists(ForStmt target_6 |
		target_6.getInitialization() instanceof ExprStmt
		and target_6.getCondition() instanceof RelationalOperation
		and target_6.getUpdate() instanceof PrefixDecrExpr
		and target_6.getStmt().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_6.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ly_set_add")
		and target_6.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="tpdf_chain"
		and target_6.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_2839
		and target_6.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vtctx_2849
		and target_6.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="1"
		and target_6.getStmt().(BlockStmt).getStmt(2) instanceof IfStmt
		and target_6.getStmt().(BlockStmt).getStmt(3) instanceof ExprStmt
		and target_6.getStmt().(BlockStmt).getStmt(4) instanceof IfStmt
		and target_6.getStmt().(BlockStmt).getStmt(5) instanceof ExprStmt
		and target_6.getStmt().(BlockStmt).getStmt(6) instanceof ExprStmt
		and target_6.getStmt().(BlockStmt).getStmt(7) instanceof ExprStmt
		and target_6.getStmt().(BlockStmt).getStmt(8) instanceof IfStmt
		and target_6.getStmt().(BlockStmt).getStmt(9) instanceof EmptyStmt
		and target_6.getStmt().(BlockStmt).getStmt(10) instanceof ExprStmt
		and target_6.getStmt().(BlockStmt).getStmt(11) instanceof LabelStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(18)=target_6 or func.getEntryPoint().(BlockStmt).getStmt(18).getFollowingStmt()=target_6)
		and target_30.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_31.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_6.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_7(Parameter vctx_2839, Variable vtpdf_chain_2852, AddressOfExpr target_32, ExprStmt target_9, Function func) {
	exists(ExprStmt target_7 |
		target_7.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="count"
		and target_7.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="tpdf_chain"
		and target_7.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_2839
		and target_7.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(ValueFieldAccess).getTarget().getName()="count"
		and target_7.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="tpdf_chain"
		and target_7.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_2839
		and target_7.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(ValueFieldAccess).getTarget().getName()="count"
		and target_7.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vtpdf_chain_2852
		and (func.getEntryPoint().(BlockStmt).getStmt(19)=target_7 or func.getEntryPoint().(BlockStmt).getStmt(19).getFollowingStmt()=target_7)
		and target_32.getOperand().(VariableAccess).getLocation().isBefore(target_7.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_7.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_9.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_9(Variable vu_2843, Variable vtpdf_chain_2852, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vu_2843
		and target_9.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(ValueFieldAccess).getTarget().getName()="count"
		and target_9.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vtpdf_chain_2852
		and target_9.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(Literal).getValue()="1"
}

predicate func_10(Variable vu_2843, BlockStmt target_24, RelationalOperation target_10) {
		 (target_10 instanceof GTExpr or target_10 instanceof LTExpr)
		and target_10.getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vu_2843
		and target_10.getGreaterOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_10.getLesserOperand().(Literal).getValue()="0"
		and target_10.getParent().(ForStmt).getStmt()=target_24
}

predicate func_11(Variable vu_2843, PrefixDecrExpr target_11) {
		target_11.getOperand().(VariableAccess).getTarget()=vu_2843
}

predicate func_12(Variable vu_2843, Variable vtctx_2849, Variable vtpdf_chain_2852, ExprStmt target_12) {
		target_12.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtctx_2849
		and target_12.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="objs"
		and target_12.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vtpdf_chain_2852
		and target_12.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vu_2843
}

predicate func_13(Variable vu_2843, Variable vtctx_2849, Variable vbasetype_2850, Variable vbase_2851, IfStmt target_13) {
		target_13.getCondition().(ValueFieldAccess).getTarget().getName()="compiled"
		and target_13.getCondition().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="type"
		and target_13.getCondition().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="tpdf"
		and target_13.getCondition().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtctx_2849
		and target_13.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbase_2851
		and target_13.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="compiled"
		and target_13.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="type"
		and target_13.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="tpdf"
		and target_13.getThen().(BlockStmt).getStmt(1).(ContinueStmt).toString() = "continue;"
		and target_13.getElse().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vbasetype_2850
		and target_13.getElse().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vu_2843
		and target_13.getElse().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(SubExpr).getLeftOperand().(ValueFieldAccess).getTarget().getName()="count"
		and target_13.getElse().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_13.getElse().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(ValueFieldAccess).getTarget().getName()="flags"
		and target_13.getElse().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="type"
		and target_13.getElse().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="tpdf"
		and target_13.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbase_2851
		and target_13.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="compiled"
		and target_13.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="compiled"
		and target_13.getElse().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(PrefixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="refcount"
		and target_13.getElse().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(PrefixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbase_2851
		and target_13.getElse().(IfStmt).getThen().(BlockStmt).getStmt(2).(ContinueStmt).toString() = "continue;"
}

predicate func_14(Parameter vtype_2840, ExprStmt target_14) {
		target_14.getExpr().(PrefixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="refcount"
		and target_14.getExpr().(PrefixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vtype_2840
}

predicate func_15(Parameter vctx_2839, Variable vret_2842, Variable vtctx_2849, Variable vbasetype_2850, Variable vtype_substmt_map, Variable vly_data_type2str, IfStmt target_15) {
		target_15.getCondition().(BitwiseAndExpr).getLeftOperand().(ComplementExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vtype_substmt_map
		and target_15.getCondition().(BitwiseAndExpr).getLeftOperand().(ComplementExpr).getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vbasetype_2850
		and target_15.getCondition().(BitwiseAndExpr).getRightOperand().(ValueFieldAccess).getTarget().getName()="flags"
		and target_15.getCondition().(BitwiseAndExpr).getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="type"
		and target_15.getCondition().(BitwiseAndExpr).getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="tpdf"
		and target_15.getCondition().(BitwiseAndExpr).getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtctx_2849
		and target_15.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ly_vlog")
		and target_15.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ctx"
		and target_15.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_2839
		and target_15.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="path"
		and target_15.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_2839
		and target_15.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(StringLiteral).getValue()="Invalid type \"%s\" restriction(s) for %s type."
		and target_15.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(PointerFieldAccess).getTarget().getName()="name"
		and target_15.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="tpdf"
		and target_15.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtctx_2849
		and target_15.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(6).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vly_data_type2str
		and target_15.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(6).(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vbasetype_2850
		and target_15.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_2842
		and target_15.getThen().(BlockStmt).getStmt(2).(GotoStmt).toString() = "goto ..."
		and target_15.getThen().(BlockStmt).getStmt(2).(GotoStmt).getName() ="cleanup"
		and target_15.getElse().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vbasetype_2850
		and target_15.getElse().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="dflt"
		and target_15.getElse().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="tpdf"
		and target_15.getElse().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtctx_2849
		and target_15.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ly_vlog")
		and target_15.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ctx"
		and target_15.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_2839
		and target_15.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="path"
		and target_15.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_2839
		and target_15.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(StringLiteral).getValue()="Invalid type \"%s\" - \"empty\" type must not have a default value (%s)."
		and target_15.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(PointerFieldAccess).getTarget().getName()="name"
		and target_15.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="tpdf"
		and target_15.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(6).(PointerFieldAccess).getTarget().getName()="dflt"
		and target_15.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(6).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="tpdf"
		and target_15.getElse().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_2842
		and target_15.getElse().(IfStmt).getThen().(BlockStmt).getStmt(2).(GotoStmt).toString() = "goto ..."
		and target_15.getElse().(IfStmt).getThen().(BlockStmt).getStmt(2).(GotoStmt).getName() ="cleanup"
}

predicate func_16(Parameter vtype_2840, Variable vbasetype_2850, ExprStmt target_16) {
		target_16.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="basetype"
		and target_16.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vtype_2840
		and target_16.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vbasetype_2850
}

predicate func_17(Parameter vtype_2840, Variable vprev_type_2851, ExprStmt target_17) {
		target_17.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vprev_type_2851
		and target_17.getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vtype_2840
}

predicate func_18(Parameter vctx_2839, Parameter voptions_2840, Parameter vtype_2840, Variable vret_2842, Variable vtctx_2849, Variable vbasetype_2850, Variable vbase_2851, ExprStmt target_18) {
		target_18.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_2842
		and target_18.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("lys_compile_type_")
		and target_18.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctx_2839
		and target_18.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="node"
		and target_18.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtctx_2849
		and target_18.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="flags"
		and target_18.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="tpdf"
		and target_18.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtctx_2849
		and target_18.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="mod"
		and target_18.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtctx_2849
		and target_18.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(PointerFieldAccess).getTarget().getName()="name"
		and target_18.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="tpdf"
		and target_18.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtctx_2849
		and target_18.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_18.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="tpdf"
		and target_18.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtctx_2849
		and target_18.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(ConditionalExpr).getCondition().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vbasetype_2850
		and target_18.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(ConditionalExpr).getCondition().(BitwiseAndExpr).getRightOperand().(BitwiseOrExpr).getValue()="15"
		and target_18.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(ConditionalExpr).getThen().(FunctionCall).getTarget().hasName("lysp_find_module")
		and target_18.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(ConditionalExpr).getThen().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ctx"
		and target_18.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(ConditionalExpr).getThen().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_2839
		and target_18.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(ConditionalExpr).getThen().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="mod"
		and target_18.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(ConditionalExpr).getThen().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtctx_2849
		and target_18.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(ConditionalExpr).getElse().(Literal).getValue()="0"
		and target_18.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vbasetype_2850
		and target_18.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(8).(VariableAccess).getTarget()=voptions_2840
		and target_18.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(9).(PointerFieldAccess).getTarget().getName()="name"
		and target_18.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(9).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="tpdf"
		and target_18.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(9).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtctx_2849
		and target_18.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(10).(VariableAccess).getTarget()=vbase_2851
		and target_18.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(11).(VariableAccess).getTarget()=vtype_2840
}

predicate func_19(Variable vret_2842, IfStmt target_19) {
		target_19.getCondition().(VariableAccess).getTarget()=vret_2842
		and target_19.getThen().(BlockStmt).getStmt(0).(GotoStmt).toString() = "goto ..."
		and target_19.getThen().(BlockStmt).getStmt(0).(GotoStmt).getName() ="cleanup"
}

predicate func_20(Variable vbase_2851, Variable vprev_type_2851, ExprStmt target_20) {
		target_20.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbase_2851
		and target_20.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vprev_type_2851
}

predicate func_21(Variable vu_2843, ExprStmt target_21) {
		target_21.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vu_2843
		and target_21.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_22(Function func, EmptyStmt target_22) {
		target_22.toString() = ";"
		and target_22.getEnclosingFunction() = func
}

predicate func_23(Function func, LabelStmt target_23) {
		target_23.toString() = "label ...:"
		and target_23.getEnclosingFunction() = func
}

predicate func_24(BlockStmt target_24) {
		target_24.getStmt(0) instanceof ExprStmt
		and target_24.getStmt(1) instanceof IfStmt
		and target_24.getStmt(2) instanceof ExprStmt
		and target_24.getStmt(3) instanceof IfStmt
		and target_24.getStmt(4) instanceof ExprStmt
}

predicate func_25(Parameter vctx_2839, Variable vtctx_2849, Variable vbasetype_2850, Variable vly_data_type2str, ExprStmt target_25) {
		target_25.getExpr().(FunctionCall).getTarget().hasName("ly_vlog")
		and target_25.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ctx"
		and target_25.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_2839
		and target_25.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="path"
		and target_25.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_2839
		and target_25.getExpr().(FunctionCall).getArgument(4).(StringLiteral).getValue()="Invalid type \"%s\" restriction(s) for %s type."
		and target_25.getExpr().(FunctionCall).getArgument(5).(PointerFieldAccess).getTarget().getName()="name"
		and target_25.getExpr().(FunctionCall).getArgument(5).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="tpdf"
		and target_25.getExpr().(FunctionCall).getArgument(5).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtctx_2849
		and target_25.getExpr().(FunctionCall).getArgument(6).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vly_data_type2str
		and target_25.getExpr().(FunctionCall).getArgument(6).(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vbasetype_2850
}

predicate func_26(Variable vret_2842, ExprStmt target_26) {
		target_26.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_2842
}

predicate func_27(Parameter vctx_2839, Variable vtctx_2849, ExprStmt target_27) {
		target_27.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("lydict_insert")
		and target_27.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ctx"
		and target_27.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_2839
		and target_27.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="units"
		and target_27.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="tpdf"
		and target_27.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtctx_2849
		and target_27.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(Literal).getValue()="0"
}

predicate func_28(Variable vret_2842, Variable vtctx_2849, IfStmt target_28) {
		target_28.getCondition().(VariableAccess).getTarget()=vret_2842
		and target_28.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("free")
		and target_28.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtctx_2849
		and target_28.getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ..."
		and target_28.getThen().(BlockStmt).getStmt(1).(GotoStmt).getName() ="cleanup"
}

predicate func_29(Variable vtctx_2849, ExprStmt target_29) {
		target_29.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vtctx_2849
}

predicate func_30(Parameter vctx_2839, Variable vbasetype_2850, Variable vly_data_type2str, ExprStmt target_30) {
		target_30.getExpr().(FunctionCall).getTarget().hasName("ly_vlog")
		and target_30.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ctx"
		and target_30.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_2839
		and target_30.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="path"
		and target_30.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_2839
		and target_30.getExpr().(FunctionCall).getArgument(4).(StringLiteral).getValue()="Invalid type restrictions for %s type."
		and target_30.getExpr().(FunctionCall).getArgument(5).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vly_data_type2str
		and target_30.getExpr().(FunctionCall).getArgument(5).(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vbasetype_2850
}

predicate func_31(Variable vtctx_2849, ExprStmt target_31) {
		target_31.getExpr().(FunctionCall).getTarget().hasName("free")
		and target_31.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtctx_2849
}

predicate func_32(Variable vtpdf_chain_2852, AddressOfExpr target_32) {
		target_32.getOperand().(VariableAccess).getTarget()=vtpdf_chain_2852
}

from Function func, Parameter vctx_2839, Parameter voptions_2840, Parameter vtype_2840, Variable vret_2842, Variable vu_2843, Variable vtctx_2849, Variable vbasetype_2850, Variable vbase_2851, Variable vprev_type_2851, Variable vtpdf_chain_2852, Variable vtype_substmt_map, Variable vly_data_type2str, ExprStmt target_9, RelationalOperation target_10, PrefixDecrExpr target_11, ExprStmt target_12, IfStmt target_13, ExprStmt target_14, IfStmt target_15, ExprStmt target_16, ExprStmt target_17, ExprStmt target_18, IfStmt target_19, ExprStmt target_20, ExprStmt target_21, EmptyStmt target_22, LabelStmt target_23, BlockStmt target_24, ExprStmt target_25, ExprStmt target_26, ExprStmt target_27, IfStmt target_28, ExprStmt target_29, ExprStmt target_30, ExprStmt target_31, AddressOfExpr target_32
where
not func_1(vu_2843, vtpdf_chain_2852, target_24, target_9)
and not func_2(vu_2843, target_10)
and not func_3(vu_2843, vtpdf_chain_2852, target_11, target_12)
and not func_4(vctx_2839, vret_2842, vtctx_2849, target_25, target_26)
and not func_5(vctx_2839, vret_2842, vu_2843, vtctx_2849, target_27, target_28, target_29)
and not func_6(vctx_2839, vtctx_2849, target_30, target_31, func)
and not func_7(vctx_2839, vtpdf_chain_2852, target_32, target_9, func)
and func_9(vu_2843, vtpdf_chain_2852, target_9)
and func_10(vu_2843, target_24, target_10)
and func_11(vu_2843, target_11)
and func_12(vu_2843, vtctx_2849, vtpdf_chain_2852, target_12)
and func_13(vu_2843, vtctx_2849, vbasetype_2850, vbase_2851, target_13)
and func_14(vtype_2840, target_14)
and func_15(vctx_2839, vret_2842, vtctx_2849, vbasetype_2850, vtype_substmt_map, vly_data_type2str, target_15)
and func_16(vtype_2840, vbasetype_2850, target_16)
and func_17(vtype_2840, vprev_type_2851, target_17)
and func_18(vctx_2839, voptions_2840, vtype_2840, vret_2842, vtctx_2849, vbasetype_2850, vbase_2851, target_18)
and func_19(vret_2842, target_19)
and func_20(vbase_2851, vprev_type_2851, target_20)
and func_21(vu_2843, target_21)
and func_22(func, target_22)
and func_23(func, target_23)
and func_24(target_24)
and func_25(vctx_2839, vtctx_2849, vbasetype_2850, vly_data_type2str, target_25)
and func_26(vret_2842, target_26)
and func_27(vctx_2839, vtctx_2849, target_27)
and func_28(vret_2842, vtctx_2849, target_28)
and func_29(vtctx_2849, target_29)
and func_30(vctx_2839, vbasetype_2850, vly_data_type2str, target_30)
and func_31(vtctx_2849, target_31)
and func_32(vtpdf_chain_2852, target_32)
and vctx_2839.getType().hasName("lysc_ctx *")
and voptions_2840.getType().hasName("int")
and vtype_2840.getType().hasName("lysc_type **")
and vret_2842.getType().hasName("LY_ERR")
and vu_2843.getType().hasName("unsigned int")
and vtctx_2849.getType().hasName("type_context *")
and vbasetype_2850.getType().hasName("LY_DATA_TYPE")
and vbase_2851.getType().hasName("lysc_type *")
and vprev_type_2851.getType().hasName("lysc_type *")
and vtpdf_chain_2852.getType().hasName("ly_set")
and vtype_substmt_map.getType() instanceof ArrayType
and vly_data_type2str.getType() instanceof ArrayType
and vctx_2839.getParentScope+() = func
and voptions_2840.getParentScope+() = func
and vtype_2840.getParentScope+() = func
and vret_2842.getParentScope+() = func
and vu_2843.getParentScope+() = func
and vtctx_2849.getParentScope+() = func
and vbasetype_2850.getParentScope+() = func
and vbase_2851.getParentScope+() = func
and vprev_type_2851.getParentScope+() = func
and vtpdf_chain_2852.getParentScope+() = func
and not vtype_substmt_map.getParentScope+() = func
and not vly_data_type2str.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
