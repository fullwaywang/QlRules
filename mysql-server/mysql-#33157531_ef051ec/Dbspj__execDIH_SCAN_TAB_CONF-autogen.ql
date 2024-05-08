/**
 * @name mysql-server-ef051ecaec7451b0aa2a9f4416488693bc62a680-Dbspj__execDIH_SCAN_TAB_CONF
 * @id cpp/mysql-server/ef051ecaec7451b0aa2a9f4416488693bc62a680/dbspjexecdihscantabconf
 * @description mysql-server-ef051ecaec7451b0aa2a9f4416488693bc62a680-storage/ndb/src/kernel/blocks/dbspj/DbspjMain.cpp-Dbspj__execDIH_SCAN_TAB_CONF mysql-#33157531
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vconf_6795, Variable vtreeNodePtr_6797, FunctionCall target_0) {
	exists(PointerFieldAccess obj_0 | obj_0=target_0.getQualifier() |
		obj_0.getTarget().getName()="m_treenode_pool"
		and obj_0.getQualifier() instanceof ThisExpr
	)
	and exists(PointerFieldAccess obj_1 | obj_1=target_0.getArgument(1) |
		obj_1.getTarget().getName()="senderData"
		and obj_1.getQualifier().(VariableAccess).getTarget()=vconf_6795
	)
	and target_0.getTarget().hasName("getPtr")
	and not target_0.getTarget().hasName("progError")
	and target_0.getArgument(0).(VariableAccess).getTarget()=vtreeNodePtr_6797
}

predicate func_1(Variable vconf_6795, Variable vtreeNodePtr_6797, ExprStmt target_21, EqualityOperation target_22, Function func) {
exists(IfStmt target_1 |
	exists(FunctionCall obj_0 | obj_0=target_1.getCondition() |
		exists(FunctionCall obj_1 | obj_1=obj_0.getArgument(0) |
			exists(PointerFieldAccess obj_2 | obj_2=obj_1.getArgument(1) |
				obj_2.getTarget().getName()="senderData"
				and obj_2.getQualifier().(VariableAccess).getTarget()=vconf_6795
			)
			and obj_1.getTarget().hasName("getGuardedPtr")
			and obj_1.getQualifier() instanceof ThisExpr
			and obj_1.getArgument(0).(VariableAccess).getTarget()=vtreeNodePtr_6797
		)
		and obj_0.getTarget().hasName("likely")
	)
	and exists(BlockStmt obj_3 | obj_3=target_1.getElse() |
		exists(DoStmt obj_4 | obj_4=obj_3.getStmt(0) |
			exists(BlockStmt obj_5 | obj_5=obj_4.getStmt() |
				obj_5.getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="theEmulatedJamIndex"
				and obj_5.getStmt(4).(ExprStmt).getExpr() instanceof Literal
				and obj_5.getStmt(5).(ExprStmt).getExpr() instanceof Literal
			)
			and obj_4.getCondition() instanceof Literal
		)
		and exists(ExprStmt obj_6 | obj_6=obj_3.getStmt(1) |
			exists(FunctionCall obj_7 | obj_7=obj_6.getExpr() |
				obj_7.getTarget().hasName("progError")
				and obj_7.getQualifier().(ThisExpr).getType() instanceof PointerType
				and obj_7.getArgument(0) instanceof Literal
				and obj_7.getArgument(1).(Literal).getValue()="2341"
				and obj_7.getArgument(2) instanceof StringLiteral
				and obj_7.getArgument(3).(StringLiteral).getValue()="getGuardedPtr(treeNodePtr, conf->senderData)"
			)
		)
	)
	and func.getEntryPoint().(BlockStmt).getAStmt()=target_1
	and target_1.getLocation().isBefore(target_21.getLocation())
	and target_1.getCondition().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_22.getLeftOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation())
)
}

/*predicate func_2(Function func) {
exists(ExprStmt target_2 |
	exists(AssignExpr obj_0 | obj_0=target_2.getExpr() |
		exists(ArrayExpr obj_1 | obj_1=obj_0.getLValue() |
			exists(PointerFieldAccess obj_2 | obj_2=obj_1.getArrayBase() |
				obj_2.getTarget().getName()="theEmulatedJam"
				and obj_2.getQualifier().(VariableAccess).getType().hasName("EmulatedJamBuffer *")
			)
			and obj_1.getArrayOffset().(PostfixIncrExpr).getOperand().(VariableAccess).getType().hasName("Uint32")
		)
		and exists(ConstructorCall obj_3 | obj_3=obj_0.getRValue() |
			obj_3.getArgument(0) instanceof Literal
			and obj_3.getArgument(1) instanceof Literal
		)
	)
	and target_2.getFollowingStmt() instanceof DeclStmt
	and target_2.getEnclosingFunction() = func
)
}

*/
/*predicate func_4(BlockStmt target_23, Function func) {
exists(ExprStmt target_4 |
	target_4.getExpr() instanceof Literal
	and target_4.getLocation().isBefore(target_23.getLocation())
	and target_4.getEnclosingFunction() = func
)
}

*/
/*predicate func_5(BlockStmt target_23, Function func) {
exists(ExprStmt target_5 |
	target_5.getExpr() instanceof Literal
	and target_5.getLocation().isBefore(target_23.getLocation())
	and target_5.getEnclosingFunction() = func
)
}

*/
predicate func_9(ExprStmt target_21, Function func) {
exists(EmptyStmt target_9 |
	func.getEntryPoint().(BlockStmt).getAStmt()=target_9
	and target_9.getLocation().isBefore(target_21.getLocation())
)
}

predicate func_11(Variable vrequestPtr_6830, Variable vfragPtr_6857, LogicalAndExpr target_24, PointerFieldAccess target_25, PointerFieldAccess target_26, ExprStmt target_27) {
exists(ExprStmt target_11 |
	exists(FunctionCall obj_0 | obj_0=target_11.getExpr() |
		obj_0.getTarget().hasName("insertGuardedPtr")
		and obj_0.getQualifier().(ThisExpr).getType() instanceof PointerType
		and obj_0.getArgument(0).(VariableAccess).getTarget()=vrequestPtr_6830
		and obj_0.getArgument(1).(VariableAccess).getTarget()=vfragPtr_6857
	)
	and exists(BlockStmt obj_1 | obj_1=target_11.getParent() |
		exists(IfStmt obj_2 | obj_2=obj_1.getParent() |
			obj_2.getThen().(BlockStmt).getStmt(4)=target_11
			and obj_2.getCondition()=target_24
		)
	)
	and target_25.getQualifier().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_11.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
	and target_11.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_26.getQualifier().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation())
	and target_27.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_11.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
)
}

predicate func_12(Variable vconf_6795, PointerFieldAccess target_12) {
	target_12.getTarget().getName()="senderData"
	and target_12.getQualifier().(VariableAccess).getTarget()=vconf_6795
	and target_12.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_14(Variable vdata_6802, ExprStmt target_14) {
	exists(AssignExpr obj_0 | obj_0=target_14.getExpr() |
		exists(ReferenceFieldAccess obj_1 | obj_1=obj_0.getLValue() |
			obj_1.getTarget().getName()="m_frags_complete"
			and obj_1.getQualifier().(VariableAccess).getTarget()=vdata_6802
		)
		and exists(ReferenceFieldAccess obj_2 | obj_2=obj_0.getRValue() |
			obj_2.getTarget().getName()="m_fragCount"
			and obj_2.getQualifier().(VariableAccess).getTarget()=vdata_6802
		)
	)
}

predicate func_15(Function func, DoStmt target_15) {
	target_15.getCondition().(Literal).getValue()="0"
	and target_15.getEnclosingFunction() = func
}

predicate func_16(Parameter vsignal_6792, Variable vrequestPtr_6830, ExprStmt target_16) {
	exists(FunctionCall obj_0 | obj_0=target_16.getExpr() |
		obj_0.getTarget().hasName("checkPrepareComplete")
		and obj_0.getQualifier().(ThisExpr).getType() instanceof PointerType
		and obj_0.getArgument(0).(VariableAccess).getTarget()=vsignal_6792
		and obj_0.getArgument(1).(VariableAccess).getTarget()=vrequestPtr_6830
	)
}

predicate func_17(Function func, ThisExpr target_17) {
	target_17.getType() instanceof PointerType
	and target_17.getEnclosingFunction() = func
}

predicate func_18(Variable vtreeNodePtr_6797, VariableAccess target_18) {
	target_18.getTarget()=vtreeNodePtr_6797
	and target_18.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_21(Function func, ExprStmt target_21) {
	target_21.getExpr() instanceof FunctionCall
	and target_21.getEnclosingFunction() = func
}

predicate func_22(Variable vtreeNodePtr_6797, EqualityOperation target_22) {
	exists(PointerFieldAccess obj_0 | obj_0=target_22.getLeftOperand() |
		exists(ValueFieldAccess obj_1 | obj_1=obj_0.getQualifier() |
			obj_1.getTarget().getName()="p"
			and obj_1.getQualifier().(VariableAccess).getTarget()=vtreeNodePtr_6797
		)
		and obj_0.getTarget().getName()="m_info"
	)
	and target_22.getRightOperand().(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("const OpInfo")
}

predicate func_23(Variable vtreeNodePtr_6797, BlockStmt target_23) {
	exists(ExprStmt obj_0 | obj_0=target_23.getStmt(1) |
		exists(AssignExpr obj_1 | obj_1=obj_0.getExpr() |
			exists(FunctionCall obj_2 | obj_2=obj_1.getRValue() |
				obj_2.getTarget().hasName("checkTableError")
				and obj_2.getQualifier().(ThisExpr).getType() instanceof PointerType
				and obj_2.getArgument(0).(VariableAccess).getTarget()=vtreeNodePtr_6797
			)
			and obj_1.getLValue().(VariableAccess).getTarget().getType().hasName("Uint32")
		)
	)
	and exists(IfStmt obj_3 | obj_3=target_23.getStmt(2) |
		exists(FunctionCall obj_4 | obj_4=obj_3.getCondition() |
			exists(EqualityOperation obj_5 | obj_5=obj_4.getArgument(0) |
				obj_5.getLeftOperand().(VariableAccess).getTarget().getType().hasName("Uint32")
				and obj_5.getRightOperand().(Literal).getValue()="0"
			)
			and obj_4.getTarget().hasName("unlikely")
		)
		and exists(BlockStmt obj_6 | obj_6=obj_3.getThen() |
			exists(DoStmt obj_7 | obj_7=obj_6.getStmt(0) |
				exists(BlockStmt obj_8 | obj_8=obj_7.getStmt() |
					obj_8.getStmt(4).(ExprStmt).getExpr() instanceof Literal
					and obj_8.getStmt(5).(ExprStmt).getExpr() instanceof Literal
				)
				and obj_7.getCondition() instanceof Literal
			)
		)
	)
}

predicate func_24(Variable vrequestPtr_6830, Variable vfragPtr_6857, LogicalAndExpr target_24) {
	exists(FunctionCall obj_0 | obj_0=target_24.getRightOperand() |
		exists(FunctionCall obj_1 | obj_1=obj_0.getArgument(0) |
			exists(PointerFieldAccess obj_2 | obj_2=obj_1.getQualifier() |
				obj_2.getTarget().getName()="m_scanfraghandle_pool"
				and obj_2.getQualifier().(ThisExpr).getType() instanceof PointerType
			)
			and exists(PointerFieldAccess obj_3 | obj_3=obj_1.getArgument(0) |
				exists(ValueFieldAccess obj_4 | obj_4=obj_3.getQualifier() |
					obj_4.getTarget().getName()="p"
					and obj_4.getQualifier().(VariableAccess).getTarget()=vrequestPtr_6830
				)
				and obj_3.getTarget().getName()="m_arena"
			)
			and obj_1.getTarget().hasName("seize")
			and obj_1.getArgument(1).(VariableAccess).getTarget()=vfragPtr_6857
		)
		and obj_0.getTarget().hasName("likely")
	)
	and target_24.getLeftOperand().(NotExpr).getValue()="1"
}

predicate func_25(Variable vrequestPtr_6830, PointerFieldAccess target_25) {
	exists(ValueFieldAccess obj_0 | obj_0=target_25.getQualifier() |
		obj_0.getTarget().getName()="p"
		and obj_0.getQualifier().(VariableAccess).getTarget()=vrequestPtr_6830
	)
	and target_25.getTarget().getName()="m_arena"
}

predicate func_26(Variable vrequestPtr_6830, PointerFieldAccess target_26) {
	exists(ValueFieldAccess obj_0 | obj_0=target_26.getQualifier() |
		obj_0.getTarget().getName()="p"
		and obj_0.getQualifier().(VariableAccess).getTarget()=vrequestPtr_6830
	)
	and target_26.getTarget().getName()="m_arena"
}

predicate func_27(Variable vfragPtr_6857, ExprStmt target_27) {
	exists(FunctionCall obj_0 | obj_0=target_27.getExpr() |
		obj_0.getTarget().hasName("addLast")
		and obj_0.getQualifier().(VariableAccess).getTarget().getType().hasName("Local_ScanFragHandle_list")
		and obj_0.getArgument(0).(VariableAccess).getTarget()=vfragPtr_6857
	)
}

from Function func, Parameter vsignal_6792, Variable vconf_6795, Variable vtreeNodePtr_6797, Variable vdata_6802, Variable vrequestPtr_6830, Variable vfragPtr_6857, FunctionCall target_0, PointerFieldAccess target_12, ExprStmt target_14, DoStmt target_15, ExprStmt target_16, ThisExpr target_17, VariableAccess target_18, ExprStmt target_21, EqualityOperation target_22, BlockStmt target_23, LogicalAndExpr target_24, PointerFieldAccess target_25, PointerFieldAccess target_26, ExprStmt target_27
where
func_0(vconf_6795, vtreeNodePtr_6797, target_0)
and not func_1(vconf_6795, vtreeNodePtr_6797, target_21, target_22, func)
and not func_9(target_21, func)
and not func_11(vrequestPtr_6830, vfragPtr_6857, target_24, target_25, target_26, target_27)
and func_12(vconf_6795, target_12)
and func_14(vdata_6802, target_14)
and func_15(func, target_15)
and func_16(vsignal_6792, vrequestPtr_6830, target_16)
and func_17(func, target_17)
and func_18(vtreeNodePtr_6797, target_18)
and func_21(func, target_21)
and func_22(vtreeNodePtr_6797, target_22)
and func_23(vtreeNodePtr_6797, target_23)
and func_24(vrequestPtr_6830, vfragPtr_6857, target_24)
and func_25(vrequestPtr_6830, target_25)
and func_26(vrequestPtr_6830, target_26)
and func_27(vfragPtr_6857, target_27)
and vsignal_6792.getType().hasName("Signal *")
and vconf_6795.getType().hasName("DihScanTabConf *")
and vtreeNodePtr_6797.getType().hasName("Ptr<TreeNode>")
and vdata_6802.getType().hasName("ScanFragData &")
and vrequestPtr_6830.getType().hasName("Ptr<Request>")
and vfragPtr_6857.getType().hasName("Ptr<ScanFragHandle>")
and vsignal_6792.getFunction() = func
and vconf_6795.(LocalVariable).getFunction() = func
and vtreeNodePtr_6797.(LocalVariable).getFunction() = func
and vdata_6802.(LocalVariable).getFunction() = func
and vrequestPtr_6830.(LocalVariable).getFunction() = func
and vfragPtr_6857.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
